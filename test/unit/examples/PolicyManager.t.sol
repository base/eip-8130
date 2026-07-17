// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {ITransactionContext, TX_CONTEXT_ADDRESS} from "../../../src/interfaces/ITransactionContext.sol";
import {Call, DefaultAccount, TRUSTED_EXECUTOR} from "../../../src/accounts/DefaultAccount.sol";

import {PolicyManager} from "../../../src/policies/PolicyManager.sol";
import {Policy} from "../../../src/policies/Policy.sol";
import {SessionPolicy} from "../../../src/policies/SessionPolicy.sol";

import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

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

/// @notice Manager-level coverage for {PolicyManager}: the per-call execute authorization boundary, independent of
///         any specific policy's enforcement logic. {SessionPolicy} is used as a concrete, minimally-configured
///         policy; policy-specific behavior is covered in SessionPolicy.t.sol.
contract PolicyManagerTest is AccountConfigurationTest {
    PolicyManager internal manager;
    SessionPolicy internal policy;

    address internal account;
    address internal target = address(0x7A46E7);
    address internal stranger = address(0xBAD);

    uint256 internal constant ROOT_PK = 0xA11CE;

    uint8 internal constant SCOPE_POLICY = 0x02;
    uint8 internal constant AUTHORIZE_ACTOR = 0x01;
    uint8 internal constant REVOKE_ACTOR = 0x02;

    function setUp() public override {
        super.setUp();
        vm.warp(1_700_000_000);

        manager = new PolicyManager(address(accountConfiguration));
        policy = new SessionPolicy(address(manager));
        account = _createAccountWithRootAndManager();
    }

    // ── Execute authorization boundary ──

    function test_execute_revertsForUnauthorizedCaller() public {
        bytes32 actorId = _installSession(1);
        // Stranger supplies a binding naming itself; it has no signed commitment for this actor.
        PolicyManager.PolicyBinding memory binding = _bindingFor(stranger, 1);
        _mockActingActor(actorId);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.NoActivePolicy.selector, actorId));
        vm.prank(stranger);
        manager.execute(binding, _action());
    }

    function test_execute_revertsInvalidBindingAccount() public {
        _installSession(1);
        PolicyManager.PolicyBinding memory binding = _binding(1); // binding.account == account
        _mockActingActor(_sessionActorId(1));

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.InvalidBindingAccount.selector, stranger, account));
        vm.prank(stranger);
        manager.execute(binding, _action());
    }

    function test_execute_revertsAfterRevoke() public {
        bytes32 actorId = _installSession(1);
        _revokePolicyActor(actorId);
        _mockActingActor(actorId);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.NoActivePolicy.selector, actorId));
        vm.prank(account);
        manager.execute(_binding(1), _action());
    }

    function test_execute_revertsForCrossAccountCommitmentReuse() public {
        // Attacker stores the victim's opaque commitment on its own account. Supplying a binding that names the
        // attacker cannot recompute to that commitment (preimage includes account), so the manager rejects.
        bytes32 victimActorId = _installSession(1);
        bytes32 victimCommitment = accountConfiguration.getPolicyCommitment(account, victimActorId);

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

    function test_execute_revertsBeforeValidAfter() public {
        uint40 validAfter = uint40(block.timestamp + 1 days);
        (bytes32 actorId, PolicyManager.PolicyBinding memory binding) = _installSessionWithWindow(1, validAfter, 0);
        _mockActingActor(actorId);

        vm.expectRevert(
            abi.encodeWithSelector(PolicyManager.OutsideValidityWindow.selector, validAfter, uint40(0), block.timestamp)
        );
        vm.prank(account);
        manager.execute(binding, _action());
    }

    function test_execute_revertsAfterValidUntil() public {
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

    function test_execute_emptyCallPlanIsNoOp() public {
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

    function test_execute_forwardsPostCallDataAfterAccountCall() public {
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

    function test_execute_revertsWhenNotDispatched() public {
        _installSession(1);
        vm.expectRevert(abi.encodeWithSelector(PolicyManager.NoActivePolicy.selector, bytes32(0)));
        vm.prank(account);
        manager.execute(_binding(1), _action());
    }

    // ── Config resolution ──

    function test_getPolicy_resolvesManagerAndCommitment() public {
        PolicyManager.PolicyBinding memory binding = _binding(9);
        bytes32 commitment = manager.commitmentOf(binding);
        bytes32 actorId = _sessionActorId(9);
        _authorizePolicyActor(actorId, commitment);

        (address resolvedTarget, bytes32 signed) = accountConfiguration.getPolicy(account, actorId);
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
        AccountConfiguration.InitialActor memory root = AccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(vm.addr(ROOT_PK))),
            authenticator: address(k1Authenticator),
            scope: 0,
            policyData: ""
        });
        AccountConfiguration.InitialActor memory mgr = AccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(address(manager))), authenticator: TRUSTED_EXECUTOR, scope: 0, policyData: ""
        });

        AccountConfiguration.InitialActor[] memory actors = new AccountConfiguration.InitialActor[](2);
        (actors[0], actors[1]) = root.actorId < mgr.actorId ? (root, mgr) : (mgr, root);

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        return accountConfiguration.createAccount(bytes32(0), bytecode, actors);
    }

    function _authorizePolicyActor(bytes32 actorId, bytes32 commitment) internal {
        _authorizePolicyActor(actorId, commitment, 0);
    }

    function _authorizePolicyActor(bytes32 actorId, bytes32 commitment, uint48 expiry) internal {
        AccountConfiguration.ActorConfig memory cfg = AccountConfiguration.ActorConfig({
            authenticator: address(k1Authenticator), scope: SCOPE_POLICY, expiry: expiry
        });
        bytes memory policyData = abi.encodePacked(address(manager), commitment);

        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: actorId, changeType: AUTHORIZE_ACTOR, data: abi.encode(cfg, policyData)
        });

        uint64 chainId = uint64(block.chainid);
        uint64 sequence = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, chainId, sequence, changes);
        accountConfiguration.applySignedActorChanges(account, chainId, changes, _buildK1Auth(ROOT_PK, digest));
    }

    function _createAttackerAccount() internal returns (address attacker, uint256 attackerOwnerPk) {
        attackerOwnerPk = 0xB0B;
        AccountConfiguration.InitialActor memory root = AccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(vm.addr(attackerOwnerPk))),
            authenticator: address(k1Authenticator),
            scope: 0,
            policyData: ""
        });
        AccountConfiguration.InitialActor memory mgr = AccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(address(manager))), authenticator: TRUSTED_EXECUTOR, scope: 0, policyData: ""
        });
        AccountConfiguration.InitialActor[] memory actors = new AccountConfiguration.InitialActor[](2);
        (actors[0], actors[1]) = root.actorId < mgr.actorId ? (root, mgr) : (mgr, root);

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        attacker = accountConfiguration.createAccount(bytes32(uint256(0xA77ACE2)), bytecode, actors);
    }

    function _authorizePolicyActorOn(address target_, uint256 ownerPk, bytes32 actorId, bytes32 commitment) internal {
        AccountConfiguration.ActorConfig memory cfg =
            AccountConfiguration.ActorConfig({authenticator: address(k1Authenticator), scope: SCOPE_POLICY, expiry: 0});
        bytes memory policyData = abi.encodePacked(address(manager), commitment);

        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: actorId, changeType: AUTHORIZE_ACTOR, data: abi.encode(cfg, policyData)
        });

        uint64 chainId = uint64(block.chainid);
        uint64 sequence = accountConfiguration.getChangeSequences(target_).local;
        bytes32 digest = _computeActorChangeBatchDigest(target_, chainId, sequence, changes);
        accountConfiguration.applySignedActorChanges(target_, chainId, changes, _buildK1Auth(ownerPk, digest));
    }

    function _revokePolicyActor(bytes32 actorId) internal {
        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({actorId: actorId, changeType: REVOKE_ACTOR, data: ""});

        uint64 chainId = uint64(block.chainid);
        uint64 sequence = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, chainId, sequence, changes);
        accountConfiguration.applySignedActorChanges(account, chainId, changes, _buildK1Auth(ROOT_PK, digest));
    }
}
