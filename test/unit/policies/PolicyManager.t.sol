// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ReentrancyGuard} from "openzeppelin/utils/ReentrancyGuard.sol";

import {Keystore} from "../../../src/Keystore.sol";
import {Scopes} from "../../../src/libraries/Scopes.sol";
import {ITransactionContext, TX_CONTEXT_ADDRESS} from "../../../src/interfaces/ITransactionContext.sol";
import {Call, IExecuteBatch} from "../../../src/interfaces/IExecuteBatch.sol";
import {IERC7821} from "../../../src/interfaces/IERC7821.sol";

import {ERC7821PolicyManager} from "../../../src/policies/ERC7821PolicyManager.sol";
import {Policy} from "../../../src/policies/Policy.sol";
import {PolicyBinding} from "../../../src/policies/PolicyBinding.sol";
import {PolicyManager} from "../../../src/policies/PolicyManager.sol";
import {SessionPolicy} from "../../../src/policies/SessionPolicy.sol";

import {KeystoreTest} from "../../lib/KeystoreTest.sol";

/// @notice A policy whose execute hook returns an empty call plan, exercising {PolicyManager._enforce}'s no-op
///         early return (no forwarded account call, no {PolicyExecuted} event).
contract EmptyPlanPolicy is Policy {
    constructor(address keystore) Policy(keystore) {}

    function _onExecute(bytes32, address, bytes calldata, bytes calldata, address)
        internal
        pure
        override
        returns (Call[] memory, bytes memory)
    {
        return (new Call[](0), "");
    }
}

/// @notice Policy that returns a single-call plan plus non-empty `postCallData`, so the manager's {onPostExecute}
///         forwarding can be asserted end-to-end.
contract PostCallPolicy is Policy {
    bytes32 public lastPostCommitment;
    address public lastPostAccount;
    bytes public lastPostCallData;
    uint256 public postCallCount;

    bytes public constant POST_PAYLOAD = hex"c0ffee";

    constructor(address keystore) Policy(keystore) {}

    function _onExecute(bytes32, address, bytes calldata, bytes calldata, address)
        internal
        pure
        override
        returns (Call[] memory calls, bytes memory postCallData)
    {
        calls = new Call[](1);
        calls[0] = Call({target: address(0xBEEF), value: 0, data: ""});
        return (calls, POST_PAYLOAD);
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
    PolicyManager internal immutable MANAGER;

    constructor(address keystore, address manager) Policy(keystore) {
        MANAGER = PolicyManager(manager);
    }

    function _onExecute(bytes32, address account, bytes calldata, bytes calldata, address)
        internal
        override
        returns (Call[] memory, bytes memory)
    {
        PolicyBinding memory dummy;
        dummy.account = account;
        // Guard is locked by the outer call -> this reverts ReentrancyGuardReentrantCall before any body check.
        MANAGER.execute(dummy, "");
        return (new Call[](0), "");
    }
}

/// @notice Exposes the default {PolicyManager._encodeCalls} hook for direct assertion.
contract PolicyManagerHarness is PolicyManager {
    constructor(address keystore) PolicyManager(keystore) {}

    function exposedEncodeCalls(address account, Call[] calldata calls) external view returns (bytes memory) {
        return _encodeCalls(account, calls);
    }
}

/// @notice Exposes the overridden {ERC7821PolicyManager._encodeCalls} hook for direct assertion.
contract ERC7821PolicyManagerHarness is ERC7821PolicyManager {
    constructor(address keystore) ERC7821PolicyManager(keystore) {}

    function exposedEncodeCalls(address account, Call[] calldata calls) external pure returns (bytes memory) {
        return _encodeCalls(account, calls);
    }
}

/// @notice Manager-level coverage for {PolicyManager}: the per-call execute authorization boundary, independent of
///         any specific policy's enforcement logic. {SessionPolicy} is used as a concrete, minimally-configured
///         policy; policy-specific behavior is covered in SessionPolicy.t.sol.
contract PolicyManagerTest is KeystoreTest {
    PolicyManager internal manager;
    SessionPolicy internal policy;
    PolicyManagerHarness internal encodeHarness;
    ERC7821PolicyManagerHarness internal erc7821Harness;

    address internal account;
    address internal target = address(0x7A46E7);
    address internal stranger = address(0xBAD);

    uint256 internal constant ROOT_PK = 0xA11CE;

    uint16 internal constant SCOPE_POLICY = Scopes.POLICY;

    function setUp() public override {
        super.setUp();
        vm.warp(1_700_000_000);

        manager = new PolicyManager(address(keystore));
        policy = new SessionPolicy(address(keystore));
        encodeHarness = new PolicyManagerHarness(address(keystore));
        erc7821Harness = new ERC7821PolicyManagerHarness(address(keystore));
        account = _createAccountWithRootAndManager();
    }

    // ── Execute authorization boundary ──

    /// @notice Verifies execute reverts when the acting actor has no signed policy commitment for the account.
    /// @dev A stranger supplies a self-named binding with no live commitment; checks NoActivePolicy(actorId).
    function test_execute_revert_unauthorizedCaller() public {
        bytes32 actorId = _installSession(1);
        // Stranger supplies a binding naming itself; it has no signed commitment for this actor.
        PolicyBinding memory binding = _bindingFor(stranger, 1);
        _mockActingActor(actorId);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.NoActivePolicy.selector, actorId));
        vm.prank(stranger);
        manager.execute(binding, _action());
    }

    /// @notice Verifies execute reverts when binding.account does not equal the calling account.
    /// @dev Checks InvalidBindingAccount(msg.sender, binding.account); the account-identity gate fires first.
    function test_execute_revert_invalidBindingAccount() public {
        _installSession(1);
        PolicyBinding memory binding = _binding(1); // binding.account == account
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

        PolicyBinding memory attackerBinding = _bindingFor(attacker, 1);
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
        (bytes32 actorId, PolicyBinding memory binding) = _installSessionWithWindow(1, validAfter, 0);
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
        (bytes32 actorId, PolicyBinding memory binding) = _installSessionWithWindow(2, 0, validUntil);
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
        ReentrantExecutePolicy evil = new ReentrantExecutePolicy(address(keystore), address(manager));
        PolicyBinding memory binding = PolicyBinding({
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
        EmptyPlanPolicy emptyPolicy = new EmptyPlanPolicy(address(keystore));
        PolicyBinding memory binding = PolicyBinding({
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
        PostCallPolicy postPolicy = new PostCallPolicy(address(keystore));
        PolicyBinding memory binding = PolicyBinding({
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

    /// @notice Verifies the policy accessors resolve the manager address and signed commitment for an authorized
    ///         policy actor.
    /// @dev Asserts Keystore.getPolicyManager / getPolicyCommitment resolve the configured policy_manager and
    ///      policy_commitment.
    function test_getPolicy_success_resolvesManagerAndCommitment() public {
        PolicyBinding memory binding = _binding(9);
        bytes32 commitment = manager.commitmentOf(binding);
        bytes32 actorId = _sessionActorId(9);
        _authorizePolicyActor(actorId, commitment);

        assertEq(keystore.getPolicyManager(account, actorId), address(manager));
        assertEq(keystore.getPolicyCommitment(account, actorId), commitment);
    }

    // ── Encoding hook ──

    /// @notice Verifies the default manager encodes a plan as executeBatch(Call[]).
    /// @dev Asserts _encodeCalls returns abi.encodeCall(IExecuteBatch.executeBatch, calls).
    function test_encodeCalls_base_producesExecuteBatch(address callTarget, uint256 value, bytes calldata data)
        public
        view
    {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: callTarget, value: value, data: data});
        assertEq(encodeHarness.exposedEncodeCalls(account, calls), abi.encodeCall(IExecuteBatch.executeBatch, (calls)));
    }

    /// @notice Verifies an ERC-7821 manager subclass overrides the encoding to execute(bytes32,bytes) batch mode.
    /// @dev Same plan, different account ABI, selected purely by which manager the account gates to.
    function test_encodeCalls_erc7821_producesBatchModeExecute(address callTarget, uint256 value, bytes calldata data)
        public
        view
    {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: callTarget, value: value, data: data});
        bytes32 modeBatch = 0x0100000000000000000000000000000000000000000000000000000000000000;
        assertEq(
            erc7821Harness.exposedEncodeCalls(account, calls),
            abi.encodeCall(IERC7821.execute, (modeBatch, abi.encode(calls)))
        );
    }

    // ── Policy-side authentication ──

    /// @notice Verifies the policy authenticates and returns a plan when called by the account's installed manager.
    /// @dev msg.sender matches the installed policy_manager and the binding recomputes to the signed commitment.
    function test_policyOnExecute_success_authenticatesInstalledManager() public {
        bytes32 actorId = _installSession(1);
        vm.prank(address(manager));
        (Call[] memory calls,) = policy.onExecute(_binding(1), actorId, _action(), account);
        assertEq(calls.length, 1);
        assertEq(calls[0].target, target);
    }

    /// @notice Verifies the policy rejects a caller that is not the account's installed manager.
    /// @dev Checks UnauthorizedManager(caller); the binding is live but msg.sender is not its policy_manager.
    function test_policyOnExecute_revert_unauthorizedManager() public {
        bytes32 actorId = _installSession(1);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Policy.UnauthorizedManager.selector, stranger));
        policy.onExecute(_binding(1), actorId, _action(), account);
    }

    /// @notice Verifies the policy rejects a binding that names a different policy.
    /// @dev Checks PolicyMismatch(address(this), binding.policy).
    function test_policyOnExecute_revert_policyMismatch() public {
        bytes32 actorId = _installSession(1);
        PolicyBinding memory wrong = _binding(1);
        wrong.policy = address(0xDEAD);
        vm.prank(address(manager));
        vm.expectRevert(abi.encodeWithSelector(Policy.PolicyMismatch.selector, address(policy), address(0xDEAD)));
        policy.onExecute(wrong, actorId, _action(), account);
    }

    /// @notice Verifies the policy rejects an actor with no live signed commitment.
    /// @dev Checks NoActivePolicy(actorId) for an actor that was never installed.
    function test_policyOnExecute_revert_noActivePolicy() public {
        bytes32 actorId = _sessionActorId(99);
        vm.prank(address(manager));
        vm.expectRevert(abi.encodeWithSelector(Policy.NoActivePolicy.selector, actorId));
        policy.onExecute(_binding(99), actorId, _action(), account);
    }

    /// @notice Verifies the policy rejects a binding that does not recompute to the signed commitment.
    /// @dev Installs salt 1, then submits binding salt 2 under actor 1; checks CommitmentMismatch(computed, signed).
    function test_policyOnExecute_revert_commitmentMismatch() public {
        bytes32 actorId = _installSession(1);
        bytes32 signed = keystore.getPolicyCommitment(account, actorId);
        PolicyBinding memory tampered = _binding(2);
        bytes32 computed = manager.commitmentOf(tampered);
        vm.prank(address(manager));
        vm.expectRevert(abi.encodeWithSelector(Policy.CommitmentMismatch.selector, computed, signed));
        policy.onExecute(tampered, actorId, _action(), account);
    }

    /// @notice Verifies the policy enforces the binding validity window itself, not relying on the manager.
    /// @dev Checks OutsideValidityWindow before validAfter, calling the policy directly as the installed manager.
    function test_policyOnExecute_revert_outsideValidityWindow() public {
        uint40 validAfter = uint40(block.timestamp + 1 days);
        (bytes32 actorId, PolicyBinding memory binding) = _installSessionWithWindow(1, validAfter, 0);
        vm.prank(address(manager));
        vm.expectRevert(
            abi.encodeWithSelector(Policy.OutsideValidityWindow.selector, validAfter, uint40(0), block.timestamp)
        );
        policy.onExecute(binding, actorId, _action(), account);
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
        scopes[0] = SessionPolicy.CallScope({target: target, selectors: new bytes4[](0)});
        return abi.encode(SessionPolicy.Config({tokenLimits: new SessionPolicy.TokenLimit[](0), callScopes: scopes}));
    }

    function _binding(uint256 salt) internal view returns (PolicyBinding memory) {
        return _bindingFor(account, salt);
    }

    function _bindingFor(address acct, uint256 salt) internal view returns (PolicyBinding memory) {
        return PolicyBinding({
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
        PolicyBinding memory binding = _binding(salt);
        actorId = _sessionActorId(salt);
        _authorizePolicyActor(actorId, manager.commitmentOf(binding), expiry);
    }

    function _installSessionWithWindow(uint256 salt, uint40 validAfter, uint40 validUntil)
        internal
        returns (bytes32 actorId, PolicyBinding memory binding)
    {
        binding = PolicyBinding({
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
            authenticator: k1Authenticator,
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
            authenticator: k1Authenticator,
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
