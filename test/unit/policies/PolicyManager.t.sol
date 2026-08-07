// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ReentrancyGuard} from "openzeppelin/utils/ReentrancyGuard.sol";

import {Keystore} from "../../../src/Keystore.sol";
import {ITransactionContext, TX_CONTEXT_ADDRESS} from "../../../src/interfaces/ITransactionContext.sol";
import {Call, DefaultAccount, TRUSTED_EXECUTOR} from "../../../src/accounts/DefaultAccount.sol";

import {PolicyManager} from "../../../src/policies/PolicyManager.sol";
import {Policy} from "../../../src/policies/Policy.sol";
import {SessionPolicy} from "../../../src/policies/SessionPolicy.sol";

import {KeystoreTest} from "../../lib/KeystoreTest.sol";

/// @notice A policy whose execute hook returns an empty call plan, exercising {PolicyManager._enforce}'s no-op
///         early return (no forwarded account call, no {PolicyExecuted} event).
contract EmptyPlanPolicy is Policy {
    constructor(address policyManager) Policy(policyManager) {}

    function _onExecute(bytes32, address, bytes calldata, bytes calldata, address)
        internal
        pure
        override
        returns (bytes memory, bytes memory)
    {
        return ("", "");
    }
}

/// @notice Policy that returns a successful empty `executeBatch` plus non-empty `postCallData`, so the manager's
///         {onPostExecute} forwarding can be asserted end-to-end.
contract PostCallPolicy is Policy {
    bytes32 public lastPostCommitment;
    address public lastPostAccount;
    bytes public lastPostCallData;
    uint256 public postCallCount;

    bytes public constant POST_PAYLOAD = hex"c0ffee";

    constructor(address policyManager) Policy(policyManager) {}

    function _onExecute(bytes32, address, bytes calldata, bytes calldata, address)
        internal
        pure
        override
        returns (bytes memory accountCallData, bytes memory postCallData)
    {
        Call[] memory calls = new Call[](0);
        return (abi.encodeCall(DefaultAccount.executeBatch, (calls)), POST_PAYLOAD);
    }

    function _onPostExecute(bytes32 commitment, address account, bytes calldata postCallData) internal override {
        lastPostCommitment = commitment;
        lastPostAccount = account;
        lastPostCallData = postCallData;
        postCallCount++;
    }
}

/// @notice Policy that re-enters {PolicyManager.execute} from within its own {onExecute} hook. The manager's shared
///         {ReentrancyGuard} must revert the nested call while the outer execution is still in flight.
contract ReentrantExecutePolicy is Policy {
    constructor(address policyManager) Policy(policyManager) {}

    function _onExecute(bytes32, address account, bytes calldata, bytes calldata, address)
        internal
        override
        returns (bytes memory, bytes memory)
    {
        PolicyManager.PolicyBinding memory dummy;
        dummy.account = account;
        // Guard is locked by the outer call -> this reverts ReentrancyGuardReentrantCall before any body check.
        PolicyManager(address(POLICY_MANAGER)).execute(dummy, "");
        return ("", "");
    }
}

/// @notice Manager-level coverage for {PolicyManager}: the per-call execute authorization boundary, independent of
///         any specific policy's enforcement logic. {SessionPolicy} is used as a concrete, minimally-configured
///         policy; policy-specific behavior is covered in SessionPolicy.t.sol.
contract PolicyManagerTest is KeystoreTest {
    PolicyManager internal manager;
    SessionPolicy internal policy;

    address internal account;
    address internal target = address(0x7A46E7);
    address internal stranger = address(0xBAD);

    uint256 internal constant ROOT_PK = 0xA11CE;

    uint8 internal constant SCOPE_POLICY = 0x02;

    function setUp() public override {
        super.setUp();
        vm.warp(1_700_000_000);

        manager = new PolicyManager(address(keystore));
        policy = new SessionPolicy(address(manager));
        account = _createAccountWithRootAndManager();
    }

    // ── Execute authorization boundary ──

    /// @notice Verifies execute reverts when the acting actor has no signed policy commitment for the account.
    /// @dev A stranger supplies a self-named binding with no live commitment; checks NoActivePolicy(actorId).
    function test_execute_revert_unauthorizedCaller() public {
        bytes32 actorId = _installSession(1);
        // Stranger supplies a binding naming itself; it has no signed commitment for this actor.
        PolicyManager.PolicyBinding memory binding = _bindingFor(stranger, 1);
        _mockActingActor(actorId);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.NoActivePolicy.selector, actorId));
        vm.prank(stranger);
        manager.execute(binding, _action());
    }

    /// @notice Verifies execute reverts when binding.account does not equal the calling account.
    /// @dev Checks InvalidBindingAccount(msg.sender, binding.account); the account-identity gate fires first.
    function test_execute_revert_invalidBindingAccount() public {
        _installSession(1);
        PolicyManager.PolicyBinding memory binding = _binding(1); // binding.account == account
        _mockActingActor(_sessionActorId(1));

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.InvalidBindingAccount.selector, stranger, account));
        vm.prank(stranger);
        manager.execute(binding, _action());
    }

    /// @notice Verifies execute reverts once the policy actor has been revoked.
    /// @dev Revoking clears the signed commitment to zero; checks NoActivePolicy(actorId).
    function test_execute_revert_afterRevoke() public {
        bytes32 actorId = _installSession(1);
        _revokePolicyActor(actorId);
        _mockActingActor(actorId);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.NoActivePolicy.selector, actorId));
        vm.prank(account);
        manager.execute(_binding(1), _action());
    }

    /// @notice Verifies execute reverts when an attacker replays a victim's opaque commitment under its own account.
    /// @dev The commitment preimage includes the account, so an attacker binding cannot recompute it; checks
    ///      BindingCommitmentMismatch(expected, actual).
    function test_execute_revert_crossAccountCommitmentReuse() public {
        // Attacker stores the victim's opaque commitment on its own account. Supplying a binding that names the
        // attacker cannot recompute to that commitment (preimage includes account), so the manager rejects.
        bytes32 victimActorId = _installSession(1);
        bytes32 victimCommitment = keystore.getPolicyCommitment(account, victimActorId);

        (address attacker, uint256 attackerOwnerPk) = _createAttackerAccount();
        bytes32 attackerActorId = keccak256(abi.encode("attacker-session", uint256(1)));
        _authorizePolicyActorOn(attacker, attackerOwnerPk, attackerActorId, victimCommitment);

        PolicyManager.PolicyBinding memory attackerBinding = _bindingFor(attacker, 1);
        bytes32 actual = manager.commitmentOf(attackerBinding);

        _mockActingActor(attackerActorId);
        vm.expectRevert(
            abi.encodeWithSelector(PolicyManager.BindingCommitmentMismatch.selector, victimCommitment, actual)
        );
        vm.prank(attacker);
        manager.execute(attackerBinding, _action());
    }

    /// @notice Verifies execute reverts before the binding's validAfter timestamp.
    /// @dev Checks OutsideValidityWindow(validAfter, 0, block.timestamp) on the window's lower bound.
    function test_execute_revert_beforeValidAfter() public {
        uint40 validAfter = uint40(block.timestamp + 1 days);
        (bytes32 actorId, PolicyManager.PolicyBinding memory binding) = _installSessionWithWindow(1, validAfter, 0);
        _mockActingActor(actorId);

        vm.expectRevert(
            abi.encodeWithSelector(PolicyManager.OutsideValidityWindow.selector, validAfter, uint40(0), block.timestamp)
        );
        vm.prank(account);
        manager.execute(binding, _action());
    }

    /// @notice Verifies execute reverts at/after the binding's validUntil timestamp.
    /// @dev Checks OutsideValidityWindow(0, validUntil, block.timestamp) on the window's exclusive upper bound.
    function test_execute_revert_afterValidUntil() public {
        uint40 validUntil = uint40(block.timestamp + 1 days);
        (bytes32 actorId, PolicyManager.PolicyBinding memory binding) = _installSessionWithWindow(2, 0, validUntil);
        _mockActingActor(actorId);

        vm.warp(uint256(validUntil));
        vm.expectRevert(
            abi.encodeWithSelector(PolicyManager.OutsideValidityWindow.selector, uint40(0), validUntil, block.timestamp)
        );
        vm.prank(account);
        manager.execute(binding, _action());
    }

    /// @notice Verifies execute reverts when a policy re-enters the manager from its own onExecute hook.
    /// @dev The shared ReentrancyGuard is locked by the outer call; checks ReentrancyGuardReentrantCall.
    function test_execute_revert_reentrantReenter() public {
        ReentrantExecutePolicy evil = new ReentrantExecutePolicy(address(manager));
        PolicyManager.PolicyBinding memory binding = PolicyManager.PolicyBinding({
            account: account, policy: address(evil), policyConfig: "", validAfter: 0, validUntil: 0, salt: 7
        });
        bytes32 actorId = _sessionActorId(7);
        _authorizePolicyActor(actorId, manager.commitmentOf(binding));
        _mockActingActor(actorId);

        vm.expectRevert(ReentrancyGuard.ReentrancyGuardReentrantCall.selector);
        vm.prank(account);
        manager.execute(binding, _action());
    }

    /// @notice Verifies execute reverts when called outside a protocol-dispatched transaction (no acting actor).
    /// @dev Absent the tx-context precompile the acting actorId is zero; checks NoActivePolicy(bytes32(0)).
    function test_execute_revert_whenNotDispatched() public {
        _installSession(1);
        vm.expectRevert(abi.encodeWithSelector(PolicyManager.NoActivePolicy.selector, bytes32(0)));
        vm.prank(account);
        manager.execute(_binding(1), _action());
    }

    /// @notice Verifies execute is a no-op when the policy returns an empty call plan.
    /// @dev _enforce early-returns before forwarding any account call; asserts no logs (no PolicyExecuted event).
    function test_execute_success_emptyCallPlanIsNoOp() public {
        EmptyPlanPolicy emptyPolicy = new EmptyPlanPolicy(address(manager));
        PolicyManager.PolicyBinding memory binding = PolicyManager.PolicyBinding({
            account: account, policy: address(emptyPolicy), policyConfig: "", validAfter: 0, validUntil: 0, salt: 42
        });
        bytes32 actorId = _sessionActorId(42);
        bytes32 commitment = manager.commitmentOf(binding);
        _authorizePolicyActor(actorId, commitment);

        _mockActingActor(actorId);
        vm.recordLogs();
        vm.prank(account);
        manager.execute(binding, _action());
        assertEq(vm.getRecordedLogs().length, 0);
    }

    /// @notice Verifies execute forwards postCallData to the policy's onPostExecute after the account call.
    /// @dev Asserts onPostExecute receives the commitment, account, and payload exactly once.
    function test_execute_success_forwardsPostCallData() public {
        PostCallPolicy postPolicy = new PostCallPolicy(address(manager));
        PolicyManager.PolicyBinding memory binding = PolicyManager.PolicyBinding({
            account: account, policy: address(postPolicy), policyConfig: "", validAfter: 0, validUntil: 0, salt: 43
        });
        bytes32 actorId = _sessionActorId(43);
        bytes32 commitment = manager.commitmentOf(binding);
        _authorizePolicyActor(actorId, commitment);

        _mockActingActor(actorId);
        vm.prank(account);
        manager.execute(binding, _action());

        assertEq(postPolicy.postCallCount(), 1);
        assertEq(postPolicy.lastPostCommitment(), commitment);
        assertEq(postPolicy.lastPostAccount(), account);
        assertEq(postPolicy.lastPostCallData(), postPolicy.POST_PAYLOAD());
    }

    // ── Config resolution ──

    /// @notice Verifies getPolicy returns the manager address and signed commitment for an authorized policy actor.
    /// @dev Asserts Keystore.getPolicy resolves the configured policy_manager and policy_commitment.
    function test_getPolicy_success_resolvesManagerAndCommitment() public {
        PolicyManager.PolicyBinding memory binding = _binding(9);
        bytes32 commitment = manager.commitmentOf(binding);
        bytes32 actorId = _sessionActorId(9);
        _authorizePolicyActor(actorId, commitment);

        (address resolvedTarget, bytes32 signed) = keystore.getPolicy(account, actorId);
        assertEq(resolvedTarget, address(manager));
        assertEq(signed, commitment);
    }

    // ── Helpers ──

    function _mockActingActor(bytes32 actorId) internal {
        vm.mockCall(
            TX_CONTEXT_ADDRESS,
            abi.encodeWithSelector(ITransactionContext.getTransactionSenderActorId.selector),
            abi.encode(actorId)
        );
    }

    function _action() internal view returns (bytes memory) {
        return abi.encode(SessionPolicy.Action({target: target, value: 0, data: ""}));
    }

    function _config() internal view returns (bytes memory) {
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = SessionPolicy.CallScope({target: target, selectorRules: new SessionPolicy.SelectorRule[](0)});
        return abi.encode(SessionPolicy.Config({tokenLimits: new SessionPolicy.TokenLimit[](0), callScopes: scopes}));
    }

    function _binding(uint256 salt) internal view returns (PolicyManager.PolicyBinding memory) {
        return _bindingFor(account, salt);
    }

    function _bindingFor(address acct, uint256 salt) internal view returns (PolicyManager.PolicyBinding memory) {
        return PolicyManager.PolicyBinding({
            account: acct, policy: address(policy), policyConfig: _config(), validAfter: 0, validUntil: 0, salt: salt
        });
    }

    function _sessionActorId(uint256 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode("session-key", salt));
    }

    function _installSession(uint256 salt) internal returns (bytes32 actorId) {
        return _installSessionWithExpiry(salt, 0);
    }

    function _installSessionWithExpiry(uint256 salt, uint48 expiry) internal returns (bytes32 actorId) {
        PolicyManager.PolicyBinding memory binding = _binding(salt);
        actorId = _sessionActorId(salt);
        _authorizePolicyActor(actorId, manager.commitmentOf(binding), expiry);
    }

    function _installSessionWithWindow(uint256 salt, uint40 validAfter, uint40 validUntil)
        internal
        returns (bytes32 actorId, PolicyManager.PolicyBinding memory binding)
    {
        binding = PolicyManager.PolicyBinding({
            account: account,
            policy: address(policy),
            policyConfig: _config(),
            validAfter: validAfter,
            validUntil: validUntil,
            salt: salt
        });
        actorId = _sessionActorId(salt);
        _authorizePolicyActor(actorId, manager.commitmentOf(binding));
    }

    function _createAccountWithRootAndManager() internal returns (address) {
        Keystore.InitialActor memory root = Keystore.InitialActor({
            actorId: bytes32(uint256(uint160(vm.addr(ROOT_PK)))),
            authenticator: address(k1Authenticator),
            scope: 0,
            policyData: ""
        });
        Keystore.InitialActor memory mgr = Keystore.InitialActor({
            actorId: bytes32(uint256(uint160(address(manager)))),
            authenticator: TRUSTED_EXECUTOR,
            scope: 0,
            policyData: ""
        });

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](2);
        (actors[0], actors[1]) = root.actorId < mgr.actorId ? (root, mgr) : (mgr, root);

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        return keystore.createAccount(bytes32(0), bytecode, actors);
    }

    function _authorizePolicyActor(bytes32 actorId, bytes32 commitment) internal {
        _authorizePolicyActor(actorId, commitment, 0);
    }

    function _authorizePolicyActor(bytes32 actorId, bytes32 commitment, uint48 expiry) internal {
        // A zero expiry (the old "no expiry") maps to UNBOUNDED, granted on a sequenced local batch.
        uint48 grant = expiry == 0 ? UNBOUNDED : expiry;
        _applyLocal(
            ROOT_PK,
            account,
            _one(
                _authorizeChange(
                    actorId,
                    address(k1Authenticator),
                    SCOPE_POLICY,
                    grant,
                    abi.encodePacked(address(manager), commitment)
                )
            )
        );
    }

    function _createAttackerAccount() internal returns (address attacker, uint256 attackerOwnerPk) {
        attackerOwnerPk = 0xB0B;
        Keystore.InitialActor memory root = Keystore.InitialActor({
            actorId: bytes32(uint256(uint160(vm.addr(attackerOwnerPk)))),
            authenticator: address(k1Authenticator),
            scope: 0,
            policyData: ""
        });
        Keystore.InitialActor memory mgr = Keystore.InitialActor({
            actorId: bytes32(uint256(uint160(address(manager)))),
            authenticator: TRUSTED_EXECUTOR,
            scope: 0,
            policyData: ""
        });
        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](2);
        (actors[0], actors[1]) = root.actorId < mgr.actorId ? (root, mgr) : (mgr, root);

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        attacker = keystore.createAccount(bytes32(uint256(0xA77ACE2)), bytecode, actors);
    }

    function _authorizePolicyActorOn(address target_, uint256 ownerPk, bytes32 actorId, bytes32 commitment) internal {
        _applyLocal(
            ownerPk,
            target_,
            _one(
                _authorizeChange(
                    actorId,
                    address(k1Authenticator),
                    SCOPE_POLICY,
                    UNBOUNDED,
                    abi.encodePacked(address(manager), commitment)
                )
            )
        );
    }

    function _revokePolicyActor(bytes32 actorId) internal {
        // A bare admin-signed revoke; it clears the slot here (no outstanding replayable grant to retire).
        _revokeActor(account, ROOT_PK, actorId);
    }
}
