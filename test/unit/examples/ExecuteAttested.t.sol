// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ReentrancyGuard} from "openzeppelin/utils/ReentrancyGuard.sol";

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {ITransactionContext, TX_CONTEXT_ADDRESS} from "../../../src/interfaces/ITransactionContext.sol";
import {Call, DefaultAccount, TRUSTED_EXECUTOR} from "../../../src/accounts/DefaultAccount.sol";

import {PolicyManager} from "../../../src/policies/PolicyManager.sol";
import {Policy} from "../../../src/policies/Policy.sol";
import {SessionPolicy} from "../../../src/policies/SessionPolicy.sol";
import {RecurringAllowance} from "../../../src/policies/RecurringAllowance.sol";

import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract AttMockERC20 {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @notice Policy that re-enters {PolicyManager.executeAttested} from within its own {onExecute} hook. The manager's
///         shared {ReentrancyGuard} must revert the nested call while the outer execution is still in flight.
contract ReentrantAttestedPolicy is Policy {
    constructor(address policyManager) Policy(policyManager) {}

    function _onExecute(bytes32, address account, bytes calldata, bytes calldata, address)
        internal
        override
        returns (bytes memory, bytes memory)
    {
        PolicyManager.PolicyBinding memory dummy;
        dummy.account = account;
        // Guard is locked by the outer call → this reverts ReentrancyGuardReentrantCall before any body check.
        PolicyManager(address(POLICY_MANAGER)).executeAttested(bytes32(0), dummy, "");
        return ("", "");
    }
}

/// @notice Coverage for {PolicyManager.executeAttested}: the account-acting path for chains with no EIP-8130
///         transaction-context precompile (e.g. ERC-4337 only). The account is `msg.sender` and attests the acting
///         `actorId`. In these tests the precompile is left un-mocked so `getTransactionSenderActorId()` returns 0
///         (a precompile-less chain), and calls are driven with a distinct `tx.origin` (a bundler / trusted executor)
///         so the self-origination guard passes — the realistic ERC-4337 shape.
contract ExecuteAttestedTest is AccountConfigurationTest {
    PolicyManager internal manager;
    SessionPolicy internal policy;
    AttMockERC20 internal token;

    address internal account;
    address internal recipient = address(0x5EE);
    address internal bundler = address(0xB0274E5); // distinct tx.origin (ERC-4337 bundler / trusted executor)

    uint256 internal constant ROOT_PK = 0xA11CE;

    uint8 internal constant SCOPE_POLICY = 0x02;
    uint8 internal constant AUTHORIZE_ACTOR = 0x01;
    uint8 internal constant REVOKE_ACTOR = 0x02;

    uint40 internal constant MONTH = 30 days;

    function setUp() public override {
        super.setUp();
        vm.warp(1_700_000_000);

        manager = new PolicyManager(address(accountConfiguration));
        policy = new SessionPolicy(address(manager));
        token = new AttMockERC20();
        account = _createAccount(bytes32(0));
    }

    // ── Happy path ──

    function test_executeAttested_happyPath_movesTokens() public {
        (bytes32 actorId, PolicyManager.PolicyBinding memory binding, bytes32 commitment) = _installSession(1, 100e6);

        vm.expectEmit(true, true, true, true);
        emit PolicyManager.PolicyExecuted(account, address(policy), commitment, account);

        vm.prank(account, bundler);
        manager.executeAttested(actorId, binding, _transfer(30e6));

        assertEq(token.balanceOf(recipient), 30e6);
        assertEq(token.balanceOf(account), 1_000e6 - 30e6);
    }

    function test_executeAttested_enforcesSpendLimit() public {
        (bytes32 actorId, PolicyManager.PolicyBinding memory binding,) = _installSession(1, 50e6);

        vm.prank(account, bundler);
        manager.executeAttested(actorId, binding, _transfer(50e6));

        // A second transfer this month exceeds the $50 cap.
        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, 51e6, 50e6));
        vm.prank(account, bundler);
        manager.executeAttested(actorId, binding, _transfer(1e6));
    }

    // ── Guards specific to the attested path ──

    function test_executeAttested_revertsOnSelfOrigination() public {
        // tx.origin == msg.sender is an EOA/7702 direct send or an 8130 self-dispatch — refused.
        (bytes32 actorId, PolicyManager.PolicyBinding memory binding,) = _installSession(1, 100e6);

        vm.expectRevert(PolicyManager.SelfOrigination.selector);
        vm.prank(account, account);
        manager.executeAttested(actorId, binding, _transfer(1));
    }

    function test_executeAttested_revertsWhenPrecompileActive() public {
        // A live precompile asserting a protocol identity means the chain is 8130 → use execute(), not this path.
        (bytes32 actorId, PolicyManager.PolicyBinding memory binding,) = _installSession(1, 100e6);
        bytes32 protocolActor = keccak256("some-protocol-actor");
        _mockActingActor(protocolActor);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.ProtocolIdentityActive.selector, protocolActor));
        vm.prank(account, bundler);
        manager.executeAttested(actorId, binding, _transfer(1));
    }

    // ── Shared authorization boundary ──

    function test_executeAttested_revertsInvalidBindingAccount() public {
        (bytes32 actorId,,) = _installSession(1, 100e6);
        // Binding names a different account than msg.sender.
        PolicyManager.PolicyBinding memory foreign = _bindingFor(address(0xF00), 1, 100e6);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.InvalidBindingAccount.selector, account, address(0xF00)));
        vm.prank(account, bundler);
        manager.executeAttested(actorId, foreign, _transfer(1));
    }

    function test_executeAttested_revertsForUnknownActor() public {
        // Actor was never gated for a policy on this account → zero signed commitment.
        (, PolicyManager.PolicyBinding memory binding,) = _installSession(1, 100e6);
        bytes32 unknown = keccak256("never-authorized");

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.NoActivePolicy.selector, unknown));
        vm.prank(account, bundler);
        manager.executeAttested(unknown, binding, _transfer(1));
    }

    function test_executeAttested_revertsBindingCommitmentMismatch() public {
        (bytes32 actorId,, bytes32 commitment) = _installSession(1, 100e6);
        // Supply a binding that recomputes to a different commitment (different salt).
        PolicyManager.PolicyBinding memory wrong = _bindingFor(account, 999, 100e6);
        bytes32 actual = manager.commitmentOf(wrong);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.BindingCommitmentMismatch.selector, commitment, actual));
        vm.prank(account, bundler);
        manager.executeAttested(actorId, wrong, _transfer(1));
    }

    function test_executeAttested_revertsAfterRevoke() public {
        (bytes32 actorId, PolicyManager.PolicyBinding memory binding,) = _installSession(1, 100e6);
        _revokePolicyActor(actorId);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.NoActivePolicy.selector, actorId));
        vm.prank(account, bundler);
        manager.executeAttested(actorId, binding, _transfer(1));
    }

    function test_executeAttested_revertsWhenActorExpired() public {
        // No protocol auth on this path, so the manager must enforce expiry locally.
        uint48 expiry = uint48(block.timestamp + 1 days);
        (bytes32 actorId, PolicyManager.PolicyBinding memory binding,) = _installSessionWithExpiry(1, 100e6, expiry);

        vm.warp(uint256(expiry) + 1);
        vm.expectRevert(abi.encodeWithSelector(PolicyManager.ActorExpired.selector, actorId));
        vm.prank(account, bundler);
        manager.executeAttested(actorId, binding, _transfer(1));
    }

    function test_executeAttested_revertsBeforeValidAfter() public {
        uint40 validAfter = uint40(block.timestamp + 1 days);
        (bytes32 actorId, PolicyManager.PolicyBinding memory binding) = _installSessionWithWindow(1, validAfter, 0);

        vm.expectRevert(
            abi.encodeWithSelector(PolicyManager.OutsideValidityWindow.selector, validAfter, uint40(0), block.timestamp)
        );
        vm.prank(account, bundler);
        manager.executeAttested(actorId, binding, _transfer(1));
    }

    function test_executeAttested_revertsAfterValidUntil() public {
        uint40 validUntil = uint40(block.timestamp + 1 days);
        (bytes32 actorId, PolicyManager.PolicyBinding memory binding) = _installSessionWithWindow(1, 0, validUntil);

        vm.warp(uint256(validUntil));
        vm.expectRevert(
            abi.encodeWithSelector(PolicyManager.OutsideValidityWindow.selector, uint40(0), validUntil, block.timestamp)
        );
        vm.prank(account, bundler);
        manager.executeAttested(actorId, binding, _transfer(1));
    }

    // ── Reentrancy ──

    function test_executeAttested_reentrancy_directReenterReverts() public {
        // A malicious policy tries to re-enter executeAttested from its own hook; the shared guard blocks it.
        ReentrantAttestedPolicy evil = new ReentrantAttestedPolicy(address(manager));
        PolicyManager.PolicyBinding memory binding = PolicyManager.PolicyBinding({
            account: account, policy: address(evil), policyConfig: "", validAfter: 0, validUntil: 0, salt: 7
        });
        bytes32 actorId = _sessionActorId(7);
        _authorizePolicyActor(actorId, manager.commitmentOf(binding), 0);

        vm.expectRevert(ReentrancyGuard.ReentrancyGuardReentrantCall.selector);
        vm.prank(account, bundler);
        manager.executeAttested(actorId, binding, "");
    }

    function test_executeAttested_reentrancy_viaSessionPolicyTargetingManagerReverts() public {
        // SessionPolicy does not blocklist the manager as a target (only the account itself). The reentrancy guard is
        // what stops it: the account's executeBatch re-enters the manager, which reverts, surfacing as CallFailed.
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] =
            SessionPolicy.CallScope({target: address(manager), selectorRules: new SessionPolicy.SelectorRule[](0)});
        bytes memory cfg =
            abi.encode(SessionPolicy.Config({tokenLimits: new SessionPolicy.TokenLimit[](0), callScopes: scopes}));

        PolicyManager.PolicyBinding memory binding = PolicyManager.PolicyBinding({
            account: account, policy: address(policy), policyConfig: cfg, validAfter: 0, validUntil: 0, salt: 8
        });
        bytes32 actorId = _sessionActorId(8);
        _authorizePolicyActor(actorId, manager.commitmentOf(binding), 0);

        PolicyManager.PolicyBinding memory inner;
        inner.account = account;
        bytes memory reenter = abi.encode(
            SessionPolicy.Action({
                target: address(manager),
                value: 0,
                data: abi.encodeCall(PolicyManager.executeAttested, (actorId, inner, ""))
            })
        );

        vm.expectRevert(DefaultAccount.CallFailed.selector);
        vm.prank(account, bundler);
        manager.executeAttested(actorId, binding, reenter);
    }

    // ── Helpers ──

    function _mockActingActor(bytes32 actorId) internal {
        vm.mockCall(
            TX_CONTEXT_ADDRESS,
            abi.encodeWithSelector(ITransactionContext.getTransactionSenderActorId.selector),
            abi.encode(actorId)
        );
    }

    function _transfer(uint256 amount) internal view returns (bytes memory) {
        return abi.encode(
            SessionPolicy.Action({
                target: address(token), value: 0, data: abi.encodeCall(AttMockERC20.transfer, (recipient, amount))
            })
        );
    }

    /// @dev SessionPolicy config: `transfer` only on `token`, with a recurring monthly spend limit.
    function _config(uint256 limit) internal view returns (bytes memory) {
        SessionPolicy.TokenLimit[] memory limits = new SessionPolicy.TokenLimit[](1);
        limits[0] = SessionPolicy.TokenLimit({token: address(token), limit: limit, period: MONTH});
        SessionPolicy.SelectorRule[] memory rules = new SessionPolicy.SelectorRule[](1);
        rules[0] = SessionPolicy.SelectorRule({selector: AttMockERC20.transfer.selector, recipients: new address[](0)});
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = SessionPolicy.CallScope({target: address(token), selectorRules: rules});
        return abi.encode(SessionPolicy.Config({tokenLimits: limits, callScopes: scopes}));
    }

    function _bindingFor(address acct, uint256 salt, uint256 limit)
        internal
        view
        returns (PolicyManager.PolicyBinding memory)
    {
        return PolicyManager.PolicyBinding({
            account: acct,
            policy: address(policy),
            policyConfig: _config(limit),
            validAfter: 0,
            validUntil: 0,
            salt: salt
        });
    }

    function _sessionActorId(uint256 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode("attested-session", salt));
    }

    function _installSession(uint256 salt, uint256 limit)
        internal
        returns (bytes32 actorId, PolicyManager.PolicyBinding memory binding, bytes32 commitment)
    {
        return _installSessionWithExpiry(salt, limit, 0);
    }

    function _installSessionWithExpiry(uint256 salt, uint256 limit, uint48 expiry)
        internal
        returns (bytes32 actorId, PolicyManager.PolicyBinding memory binding, bytes32 commitment)
    {
        binding = _bindingFor(account, salt, limit);
        actorId = _sessionActorId(salt);
        commitment = manager.commitmentOf(binding);
        _authorizePolicyActor(actorId, commitment, expiry);
    }

    function _installSessionWithWindow(uint256 salt, uint40 validAfter, uint40 validUntil)
        internal
        returns (bytes32 actorId, PolicyManager.PolicyBinding memory binding)
    {
        binding = PolicyManager.PolicyBinding({
            account: account,
            policy: address(policy),
            policyConfig: _config(100e6),
            validAfter: validAfter,
            validUntil: validUntil,
            salt: salt
        });
        actorId = _sessionActorId(salt);
        _authorizePolicyActor(actorId, manager.commitmentOf(binding), 0);
    }

    function _createAccount(bytes32 salt) internal returns (address acct) {
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
        acct = accountConfiguration.createAccount(salt, bytecode, actors);
        token.mint(acct, 1_000e6);
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
        _applyAsRoot(changes);
    }

    function _revokePolicyActor(bytes32 actorId) internal {
        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({actorId: actorId, changeType: REVOKE_ACTOR, data: ""});
        _applyAsRoot(changes);
    }

    function _applyAsRoot(AccountConfiguration.ActorChange[] memory changes) internal {
        uint64 chainId = uint64(block.chainid);
        uint64 sequence = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, chainId, sequence, changes);
        accountConfiguration.applySignedActorChanges(account, chainId, changes, _buildK1Auth(ROOT_PK, digest));
    }
}
