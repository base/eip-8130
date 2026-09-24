// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ReentrancyGuard} from "openzeppelin/utils/ReentrancyGuard.sol";

import {Keystore} from "../../../src/Keystore.sol";
import {Scopes} from "../../../src/libraries/Scopes.sol";
import {ITransactionContext, TX_CONTEXT_ADDRESS} from "../../../src/interfaces/ITransactionContext.sol";
import {Call, IExecuteBatch} from "../../../src/interfaces/IExecuteBatch.sol";
import {IERC7821} from "../../../src/interfaces/IERC7821.sol";

import {ERC7821Encoder} from "../../../src/policies/ERC7821Encoder.sol";
import {Policy} from "../../../src/policies/Policy.sol";
import {PolicyBinding} from "../../../src/policies/PolicyBinding.sol";
import {SessionPolicy} from "../../../src/policies/SessionPolicy.sol";

import {KeystoreTest} from "../../lib/KeystoreTest.sol";

/// @notice A policy whose execute hook returns an empty call plan, exercising {Policy._enforce}'s no-op
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

    function _onPostExecute(bytes32 commitment, address account, bytes memory postCallData) internal override {
        lastPostCommitment = commitment;
        lastPostAccount = account;
        lastPostCallData = postCallData;
        postCallCount++;
    }
}

/// @notice Policy that re-enters {Policy.execute} from within its own {onExecute} hook. The manager's shared
///         {ReentrancyGuard} must revert the nested call while the outer execution is still in flight.
contract ReentrantExecutePolicy is Policy {
    constructor(address keystore) Policy(keystore) {}

    function _onExecute(bytes32, address account, bytes calldata, bytes calldata, address)
        internal
        override
        returns (Call[] memory, bytes memory)
    {
        PolicyBinding memory dummy;
        dummy.account = account;
        // Guard is locked by the outer call -> re-entering ourselves reverts ReentrancyGuardReentrantCall before any
        // body check.
        this.execute(dummy, "");
        return (new Call[](0), "");
    }
}

/// @notice Trivial concrete {Policy} exposing the internal {_encodeFor} dispatch encoder, so both the default
///         (executeBatch) and transformer (IPolicyCallEncoder) encodings can be asserted directly.
contract EncodeHarness is Policy {
    constructor(address keystore) Policy(keystore) {}

    function _onExecute(bytes32, address, bytes calldata, bytes calldata, address)
        internal
        pure
        override
        returns (Call[] memory, bytes memory)
    {
        return (new Call[](0), "");
    }

    function exposedEncodeFor(PolicyBinding calldata binding, Call[] calldata calls)
        external
        view
        returns (bytes memory)
    {
        return _encodeFor(binding, calls);
    }
}

/// @notice Manager-level coverage for {PolicyManager}: the per-call execute authorization boundary, independent of
///         any specific policy's enforcement logic. {SessionPolicy} is used as a concrete, minimally-configured
///         policy; policy-specific behavior is covered in SessionPolicy.t.sol.
contract PolicyTest is KeystoreTest {
    SessionPolicy internal policy;
    EncodeHarness internal encodeHarness;

    address internal account;
    address internal target = address(0x7A46E7);
    address internal stranger = address(0xBAD);

    uint256 internal constant ROOT_PK = 0xA11CE;

    uint16 internal constant SCOPE_POLICY = Scopes.POLICY;

    function setUp() public override {
        super.setUp();
        vm.warp(1_700_000_000);

        policy = new SessionPolicy(address(keystore));
        encodeHarness = new EncodeHarness(address(keystore));
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

        vm.expectRevert(abi.encodeWithSelector(Policy.NoActivePolicy.selector, actorId));
        vm.prank(stranger);
        policy.execute(binding, _action());
    }

    /// @notice Verifies execute reverts when binding.account does not equal the calling account.
    /// @dev Checks InvalidBindingAccount(msg.sender, binding.account); the account-identity gate fires first.
    function test_execute_revert_invalidBindingAccount() public {
        _installSession(1);
        PolicyBinding memory binding = _binding(1); // binding.account == account
        _mockActingActor(_sessionActorId(1));

        vm.expectRevert(abi.encodeWithSelector(Policy.InvalidBindingAccount.selector, stranger, account));
        vm.prank(stranger);
        policy.execute(binding, _action());
    }

    /// @notice Verifies execute reverts once the policy actor has been revoked.
    /// @dev Revoking clears the signed commitment to zero; checks NoActivePolicy(actorId).
    function test_execute_revert_afterRevoke() public {
        bytes32 actorId = _installSession(1);
        _revokePolicyActor(actorId);
        _mockActingActor(actorId);

        vm.expectRevert(abi.encodeWithSelector(Policy.NoActivePolicy.selector, actorId));
        vm.prank(account);
        policy.execute(_binding(1), _action());
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
        bytes32 actual = policy.commitmentOf(attackerBinding);

        _mockActingActor(attackerActorId);
        vm.expectRevert(abi.encodeWithSelector(Policy.BindingCommitmentMismatch.selector, victimCommitment, actual));
        vm.prank(attacker);
        policy.execute(attackerBinding, _action());
    }

    /// @notice Verifies execute reverts before the binding's validAfter timestamp.
    /// @dev Checks OutsideValidityWindow(validAfter, 0, block.timestamp) on the window's lower bound.
    function test_execute_revert_beforeValidAfter() public {
        uint40 validAfter = uint40(block.timestamp + 1 days);
        (bytes32 actorId, PolicyBinding memory binding) = _installSessionWithWindow(1, validAfter, 0);
        _mockActingActor(actorId);

        vm.expectRevert(
            abi.encodeWithSelector(Policy.OutsideValidityWindow.selector, validAfter, uint40(0), block.timestamp)
        );
        vm.prank(account);
        policy.execute(binding, _action());
    }

    /// @notice Verifies execute reverts at/after the binding's validUntil timestamp.
    /// @dev Checks OutsideValidityWindow(0, validUntil, block.timestamp) on the window's exclusive upper bound.
    function test_execute_revert_afterValidUntil() public {
        uint40 validUntil = uint40(block.timestamp + 1 days);
        (bytes32 actorId, PolicyBinding memory binding) = _installSessionWithWindow(2, 0, validUntil);
        _mockActingActor(actorId);

        vm.warp(uint256(validUntil));
        vm.expectRevert(
            abi.encodeWithSelector(Policy.OutsideValidityWindow.selector, uint40(0), validUntil, block.timestamp)
        );
        vm.prank(account);
        policy.execute(binding, _action());
    }

    /// @notice Verifies execute reverts when a policy re-enters the manager from its own onExecute hook.
    /// @dev The shared ReentrancyGuard is locked by the outer call; checks ReentrancyGuardReentrantCall.
    function test_execute_revert_reentrantReenter() public {
        ReentrantExecutePolicy evil = new ReentrantExecutePolicy(address(keystore));
        PolicyBinding memory binding = PolicyBinding({
            account: account,
            policy: address(evil),
            policyConfig: "",
            validAfter: 0,
            validUntil: 0,
            salt: 7,
            transformer: address(0)
        });
        bytes32 actorId = _sessionActorId(7);
        _authorizePolicyActorWithManager(actorId, address(evil), policy.commitmentOf(binding));
        _mockActingActor(actorId);

        vm.expectRevert(ReentrancyGuard.ReentrancyGuardReentrantCall.selector);
        vm.prank(account);
        evil.execute(binding, _action());
    }

    /// @notice Verifies execute reverts when called outside a protocol-dispatched transaction (no acting actor).
    /// @dev Absent the tx-context precompile the acting actorId is zero; checks NoActivePolicy(bytes32(0)).
    function test_execute_revert_whenNotDispatched() public {
        _installSession(1);
        vm.expectRevert(abi.encodeWithSelector(Policy.NoActivePolicy.selector, bytes32(0)));
        vm.prank(account);
        policy.execute(_binding(1), _action());
    }

    /// @notice Verifies execute is a no-op when the policy returns an empty call plan.
    /// @dev _enforce early-returns before forwarding any account call; asserts no logs (no PolicyExecuted event).
    function test_execute_success_emptyCallPlanIsNoOp() public {
        EmptyPlanPolicy emptyPolicy = new EmptyPlanPolicy(address(keystore));
        PolicyBinding memory binding = PolicyBinding({
            account: account,
            policy: address(emptyPolicy),
            policyConfig: "",
            validAfter: 0,
            validUntil: 0,
            salt: 42,
            transformer: address(0)
        });
        bytes32 actorId = _sessionActorId(42);
        bytes32 commitment = policy.commitmentOf(binding);
        _authorizePolicyActorWithManager(actorId, address(emptyPolicy), commitment);

        _mockActingActor(actorId);
        vm.recordLogs();
        vm.prank(account);
        emptyPolicy.execute(binding, _action());
        assertEq(vm.getRecordedLogs().length, 0);
    }

    /// @notice Verifies execute forwards postCallData to the policy's onPostExecute after the account call.
    /// @dev Asserts onPostExecute receives the commitment, account, and payload exactly once.
    function test_execute_success_forwardsPostCallData() public {
        PostCallPolicy postPolicy = new PostCallPolicy(address(keystore));
        PolicyBinding memory binding = PolicyBinding({
            account: account,
            policy: address(postPolicy),
            policyConfig: "",
            validAfter: 0,
            validUntil: 0,
            salt: 43,
            transformer: address(0)
        });
        bytes32 actorId = _sessionActorId(43);
        bytes32 commitment = policy.commitmentOf(binding);
        _registerOperationalActor(address(postPolicy));
        _authorizePolicyActorWithManager(actorId, address(postPolicy), commitment);

        _mockActingActor(actorId);
        vm.prank(account);
        postPolicy.execute(binding, _action());

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
        bytes32 commitment = policy.commitmentOf(binding);
        bytes32 actorId = _sessionActorId(9);
        _authorizePolicyActor(actorId, commitment);

        assertEq(keystore.getPolicyManager(account, actorId), address(policy));
        assertEq(keystore.getPolicyCommitment(account, actorId), commitment);
    }

    // ── Encoding hook ──

    /// @notice Verifies the default dispatch encoding (transformer == address(0)) is executeBatch(Call[]).
    /// @dev Asserts _encodeFor returns abi.encodeCall(IExecuteBatch.executeBatch, calls) for a default binding.
    function test_encodeFor_default_producesExecuteBatch(address callTarget, uint256 value, bytes calldata data)
        public
        view
    {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: callTarget, value: value, data: data});
        PolicyBinding memory binding = _binding(1); // transformer == address(0)
        assertEq(encodeHarness.exposedEncodeFor(binding, calls), abi.encodeCall(IExecuteBatch.executeBatch, (calls)));
    }

    /// @notice Verifies a non-zero binding.transformer routes encoding through the {IPolicyCallEncoder} — here the
    ///         {ERC7821Encoder}, producing execute(bytes32,bytes) batch-mode calldata.
    /// @dev Same plan, different account ABI, selected purely by the binding's committed transformer.
    function test_encodeFor_transformer_producesBatchModeExecute(address callTarget, uint256 value, bytes calldata data)
        public
    {
        ERC7821Encoder enc = new ERC7821Encoder();
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: callTarget, value: value, data: data});
        bytes32 modeBatch = 0x0100000000000000000000000000000000000000000000000000000000000000;
        bytes memory expected = abi.encodeCall(IERC7821.execute, (modeBatch, abi.encode(calls)));

        PolicyBinding memory binding = _binding(1);
        binding.transformer = address(enc);
        assertEq(encodeHarness.exposedEncodeFor(binding, calls), expected);
        // The encoder is a standalone, staticcallable pure contract.
        assertEq(enc.encodeCalls(account, calls), expected);
    }

    // ── Policy-side authentication ──

    /// @notice Verifies the self-executing policy authenticates and forwards the plan on the account-acting path.
    /// @dev The account is the caller, the acting actor is the installed session, and the binding recomputes to the
    ///      signed commitment; a PolicyExecuted event marks the forwarded batch.
    function test_execute_success_authenticatesAndForwards() public {
        bytes32 actorId = _installSession(1);
        _mockActingActor(actorId);
        vm.expectEmit(true, true, false, false);
        emit Policy.PolicyExecuted(account, address(policy), bytes32(0), account);
        vm.prank(account);
        policy.execute(_binding(1), _action());
    }

    /// @notice Verifies the policy refuses when the actor is gated to a different manager, not this policy.
    /// @dev The actor's policy_manager is another address, so the self-executing policy is not the installed manager
    ///      and reverts NoActivePolicy.
    function test_execute_revert_policyNotInstalledManager() public {
        bytes32 actorId = _sessionActorId(11);
        PolicyBinding memory binding = _binding(11);
        _authorizePolicyActorWithManager(actorId, address(0xDEAD), policy.commitmentOf(binding));
        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(Policy.NoActivePolicy.selector, actorId));
        vm.prank(account);
        policy.execute(binding, _action());
    }

    /// @notice Verifies the policy rejects a binding that names a different policy.
    /// @dev Checks PolicyMismatch(address(this), binding.policy); the check fires before any Keystore read.
    function test_execute_revert_policyMismatch() public {
        bytes32 actorId = _installSession(1);
        PolicyBinding memory wrong = _binding(1);
        wrong.policy = address(0xDEAD);
        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(Policy.PolicyMismatch.selector, address(policy), address(0xDEAD)));
        vm.prank(account);
        policy.execute(wrong, _action());
    }

    /// @notice Verifies the policy rejects an actor with no live signed commitment.
    /// @dev Checks NoActivePolicy(actorId) for an actor that was never installed.
    function test_execute_revert_noActivePolicy() public {
        bytes32 actorId = _sessionActorId(99);
        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(Policy.NoActivePolicy.selector, actorId));
        vm.prank(account);
        policy.execute(_binding(99), _action());
    }

    /// @notice Verifies the policy rejects a binding that does not recompute to the signed commitment.
    /// @dev Installs salt 1, then submits binding salt 2 under actor 1; checks BindingCommitmentMismatch(signed,
    ///      computed).
    function test_execute_revert_commitmentMismatch() public {
        bytes32 actorId = _installSession(1);
        bytes32 signed = keystore.getPolicyCommitment(account, actorId);
        PolicyBinding memory tampered = _binding(2);
        bytes32 computed = policy.commitmentOf(tampered);
        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(Policy.BindingCommitmentMismatch.selector, signed, computed));
        vm.prank(account);
        policy.execute(tampered, _action());
    }

    /// @notice Verifies the self-executing policy enforces the binding validity window on the execute path.
    /// @dev Checks OutsideValidityWindow before validAfter.
    function test_execute_revert_windowEnforcedByPolicy() public {
        uint40 validAfter = uint40(block.timestamp + 1 days);
        (bytes32 actorId, PolicyBinding memory binding) = _installSessionWithWindow(1, validAfter, 0);
        _mockActingActor(actorId);
        vm.expectRevert(
            abi.encodeWithSelector(Policy.OutsideValidityWindow.selector, validAfter, uint40(0), block.timestamp)
        );
        vm.prank(account);
        policy.execute(binding, _action());
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
            account: acct,
            policy: address(policy),
            policyConfig: _config(),
            validAfter: 0,
            validUntil: 0,
            salt: salt,
            transformer: address(0)
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
        _authorizePolicyActor(actorId, policy.commitmentOf(binding), expiry);
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
            salt: salt,
            transformer: address(0)
        });
        actorId = _sessionActorId(salt);
        _authorizePolicyActor(actorId, policy.commitmentOf(binding));
    }

    function _createAccountWithRootAndManager() internal returns (address) {
        Keystore.InitialActor memory root = Keystore.InitialActor({
            actorId: bytes32(uint256(uint160(vm.addr(ROOT_PK)))),
            authenticator: address(k1Authenticator),
            scope: 0,
            policyData: ""
        });
        Keystore.InitialActor memory mgr = Keystore.InitialActor({
            actorId: bytes32(uint256(uint160(address(policy)))),
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
                    abi.encodePacked(address(policy), commitment)
                )
            )
        );
    }

    /// @dev Authorize a policy actor gated to an explicit `managerAddr` (used both to gate an actor to a specific
    ///      self-executing policy instance, and to gate to a non-policy address to assert the policy refuses when it
    ///      is not the installed manager).
    function _authorizePolicyActorWithManager(bytes32 actorId, address managerAddr, bytes32 commitment) internal {
        _applyLocal(
            ROOT_PK,
            account,
            _one(
                _authorizeChange(
                    actorId,
                    address(k1Authenticator),
                    SCOPE_POLICY,
                    UNBOUNDED,
                    abi.encodePacked(managerAddr, commitment)
                )
            )
        );
    }

    /// @dev Register `a` as a live, operational k1 actor of the account so it may drive `executeBatch` directly. A
    ///      self-executing policy that forwards a plan must itself be an authorized caller of the account.
    function _registerOperationalActor(address a) internal {
        _applyLocal(
            ROOT_PK,
            account,
            _one(_authorizeChange(bytes32(uint256(uint160(a))), address(k1Authenticator), 0, UNBOUNDED, ""))
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
            actorId: bytes32(uint256(uint160(address(policy)))),
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
                    abi.encodePacked(address(policy), commitment)
                )
            )
        );
    }

    function _revokePolicyActor(bytes32 actorId) internal {
        // A bare admin-signed revoke; it clears the slot here (no outstanding replayable grant to retire).
        _revokeActor(account, ROOT_PK, actorId);
    }
}
