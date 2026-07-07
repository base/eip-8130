// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {ITransactionContext, TX_CONTEXT_ADDRESS} from "../../../src/interfaces/ITransactionContext.sol";
import {TRUSTED_EXECUTOR} from "../../../src/accounts/DefaultAccount.sol";

import {PolicyManager} from "../../../src/examples/policies/PolicyManager.sol";
import {SessionPolicy} from "../../../src/examples/policies/SessionPolicy.sol";

import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

/// @notice Manager-level coverage for {PolicyManager}: the install authorization checks and the per-call execute
///         authorization boundary, independent of any specific policy's enforcement logic. {SessionPolicy} is used as
///         a concrete, minimally-configured policy; policy-specific behavior is covered in SessionPolicy.t.sol.
contract PolicyManagerTest is AccountConfigurationTest {
    PolicyManager internal manager;
    SessionPolicy internal policy;

    address internal account;
    address internal target = address(0x7A46E7);
    address internal stranger = address(0xBAD);

    uint256 internal constant ROOT_PK = 0xA11CE;

    uint8 internal constant SCOPE_SENDER = 0x02;
    uint8 internal constant POLICY_GATED = 0x01;
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
        // The protocol reports this actor, but a stranger account has no commitment for it, so execute rejects it.
        _mockActingActor(actorId);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.NoActivePolicy.selector, actorId));
        vm.prank(stranger);
        manager.execute(address(policy), _action());
    }

    function test_execute_revertsAfterRevoke() public {
        bytes32 actorId = _installSession(1);
        _revokePolicyActor(actorId);
        _mockActingActor(actorId);

        // Revoke cleared the policy slots; the per-call commitment read now resolves to zero.
        vm.expectRevert(abi.encodeWithSelector(PolicyManager.NoActivePolicy.selector, actorId));
        vm.prank(account);
        manager.execute(address(policy), _action());
    }

    function test_execute_revertsForCrossAccountCommitmentReuse() public {
        // Victim installs a binding for itself; record.account = victim. Note: AccountConfiguration stores the
        // commitment as opaque bytes, so an attacker can register an actor on their *own* account that points at the
        // victim's commitment value + this manager. The manager must reject when the executing account is not the
        // one the binding was installed for, otherwise the attacker could drive (and exhaust) the victim's
        // commitment-keyed policy state — e.g. a shared spend counter.
        bytes32 victimActorId = _installSession(1);
        bytes32 victimCommitment = ACCOUNT_CONFIGURATION_commitment(victimActorId);

        // Build an attacker account that "authorizes" an actor with the victim's commitment value and this manager.
        (address attacker, uint256 attackerOwnerPk) = _createAttackerAccount();
        bytes32 attackerActorId = keccak256(abi.encode("attacker-session", uint256(1)));
        _authorizePolicyActorOn(attacker, attackerOwnerPk, attackerActorId, victimCommitment);

        _mockActingActor(attackerActorId);
        vm.expectRevert(abi.encodeWithSelector(PolicyManager.CommitmentAccountMismatch.selector, account, attacker));
        vm.prank(attacker);
        manager.execute(address(policy), _action());
    }

    // ── Install authorization ──

    function test_install_isPermissionless_anyCallerForAuthorizedBinding() public {
        // Install is gated by the account's signed commitment, not by msg.sender: once the account has authorized the
        // actor's commitment, a third party (e.g. a subscription provider) can submit the install itself.
        PolicyManager.PolicyBinding memory binding = _binding(1);
        bytes32 actorId = _sessionActorId(1);
        bytes32 commitment = manager.commitmentOf(binding);
        _authorizePolicyActor(actorId, commitment);

        vm.prank(stranger);
        manager.install(actorId, binding);

        assertTrue(manager.getPolicyRecord(address(policy), commitment).installed);
    }

    function test_install_revertsWhenAlreadyInstalled() public {
        // One-shot per commitment: re-installing the same binding cannot reset its accounting.
        PolicyManager.PolicyBinding memory binding = _binding(1);
        bytes32 actorId = _sessionActorId(1);
        bytes32 commitment = manager.commitmentOf(binding);
        _authorizePolicyActor(actorId, commitment);
        vm.prank(account);
        manager.install(actorId, binding);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.PolicyAlreadyInstalled.selector, commitment));
        vm.prank(account);
        manager.install(actorId, binding);
    }

    function test_install_revertsWhenCommitmentNotAuthorized() public {
        // Binding is well-formed, but the account never authorized an actor committing to it.
        PolicyManager.PolicyBinding memory binding = _binding(7);
        bytes32 actorId = _sessionActorId(7);

        vm.expectRevert(
            abi.encodeWithSelector(PolicyManager.CommitmentNotAuthorized.selector, actorId, address(0), bytes32(0))
        );
        vm.prank(account);
        manager.install(actorId, binding);
    }

    // ── Config resolution ──

    function test_getPolicy_resolvesManagerAndCommitment() public {
        PolicyManager.PolicyBinding memory binding = _binding(9);
        bytes32 commitment = manager.commitmentOf(binding);
        bytes32 actorId = _sessionActorId(9);
        _authorizePolicyActor(actorId, commitment);

        (uint8 policyType, address resolvedTarget, bytes32 signed) = accountConfiguration.getPolicy(account, actorId);
        assertEq(policyType, accountConfiguration.POLICY_GATED());
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

    /// @dev A trivially-passing per-use action: an unrestricted call to `target` (the binding allows any selector).
    function _action() internal view returns (bytes memory) {
        return abi.encode(SessionPolicy.Action({target: target, value: 0, data: ""}));
    }

    /// @dev A minimal SessionPolicy config: a single call scope on `target` allowing any selector, no spend limits.
    function _config() internal view returns (bytes memory) {
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = SessionPolicy.CallScope({target: target, selectorRules: new SessionPolicy.SelectorRule[](0)});
        return abi.encode(SessionPolicy.Config({tokenLimits: new SessionPolicy.TokenLimit[](0), callScopes: scopes}));
    }

    function _binding(uint256 salt) internal view returns (PolicyManager.PolicyBinding memory) {
        return PolicyManager.PolicyBinding({
            account: account, policy: address(policy), policyConfig: _config(), validAfter: 0, validUntil: 0, salt: salt
        });
    }

    function _sessionActorId(uint256 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode("session-key", salt));
    }

    function _installSession(uint256 salt) internal returns (bytes32 actorId) {
        PolicyManager.PolicyBinding memory binding = _binding(salt);
        actorId = _sessionActorId(salt);
        _authorizePolicyActor(actorId, manager.commitmentOf(binding));
        vm.prank(account);
        manager.install(actorId, binding);
    }

    function _createAccountWithRootAndManager() internal returns (address) {
        AccountConfiguration.InitialActor memory root = AccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(vm.addr(ROOT_PK))), authenticator: address(k1Authenticator)
        });
        AccountConfiguration.InitialActor memory mgr = AccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(address(manager))), authenticator: TRUSTED_EXECUTOR
        });

        AccountConfiguration.InitialActor[] memory actors = new AccountConfiguration.InitialActor[](2);
        (actors[0], actors[1]) = root.actorId < mgr.actorId ? (root, mgr) : (mgr, root);

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        return accountConfiguration.createAccount(bytes32(0), bytecode, actors);
    }

    function _authorizePolicyActor(bytes32 actorId, bytes32 commitment) internal {
        AccountConfiguration.ActorConfig memory cfg = AccountConfiguration.ActorConfig({
            authenticator: address(k1Authenticator), scope: SCOPE_SENDER, expiry: 0, policyType: POLICY_GATED
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

    function ACCOUNT_CONFIGURATION_commitment(bytes32 actorId) internal view returns (bytes32) {
        return accountConfiguration.getPolicyCommitment(account, actorId);
    }

    /// @dev Build a second account owned by a distinct root key (the "attacker"), with this manager registered as
    ///      an execution-enabled actor (`TRUSTED_EXECUTOR`).
    function _createAttackerAccount() internal returns (address attacker, uint256 attackerOwnerPk) {
        attackerOwnerPk = 0xB0B;
        AccountConfiguration.InitialActor memory root = AccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(vm.addr(attackerOwnerPk))), authenticator: address(k1Authenticator)
        });
        AccountConfiguration.InitialActor memory mgr = AccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(address(manager))), authenticator: TRUSTED_EXECUTOR
        });
        AccountConfiguration.InitialActor[] memory actors = new AccountConfiguration.InitialActor[](2);
        (actors[0], actors[1]) = root.actorId < mgr.actorId ? (root, mgr) : (mgr, root);

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        attacker = accountConfiguration.createAccount(bytes32(uint256(0xA77ACE2)), bytecode, actors);
    }

    /// @dev Variant of {_authorizePolicyActor} that operates on an arbitrary `target` account signed by its owner.
    ///      Used to register a victim's commitment value on a different account — the cross-account reuse case.
    function _authorizePolicyActorOn(address target_, uint256 ownerPk, bytes32 actorId, bytes32 commitment) internal {
        AccountConfiguration.ActorConfig memory cfg = AccountConfiguration.ActorConfig({
            authenticator: address(k1Authenticator), scope: SCOPE_SENDER, expiry: 0, policyType: POLICY_GATED
        });
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
