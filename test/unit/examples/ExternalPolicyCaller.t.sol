// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "../../../src/Keystore.sol";
import {TRUSTED_EXECUTOR} from "../../../src/accounts/DefaultAccount.sol";

import {PolicyManager, EXTERNAL_POLICY_AUTHENTICATOR} from "../../../src/policies/PolicyManager.sol";
import {SessionPolicy} from "../../../src/policies/SessionPolicy.sol";
import {RecurringAllowance} from "../../../src/policies/RecurringAllowance.sol";

import {KeystoreTest} from "../../lib/KeystoreTest.sol";

contract ExtMockERC20 {
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

/// @notice Exercises the external-caller flow of {PolicyManager}: a party that is *not* a key on the account (e.g. a
///         subscription provider) is authorized by accounts to pull within a policy, and drives one or many accounts
///         via {PolicyManager.executeFor} / {executeForMany}. Identity is the caller itself
///         (`actorId == bytes20(msg.sender)`); the provider actor is registered with `EXTERNAL_POLICY_AUTHENTICATOR`
///         so it can only act through the manager, never directly.
contract ExternalPolicyCallerTest is KeystoreTest {
    PolicyManager internal manager;
    SessionPolicy internal policy;
    ExtMockERC20 internal token;

    address internal provider = address(0x9405); // the external caller (subscription provider)
    address internal recipient = address(0x5EE);

    uint256 internal constant ROOT_PK = 0xA11CE;
    uint8 internal constant SCOPE_SENDER = 0x01;
    uint8 internal constant SCOPE_POLICY = 0x02;
    uint8 internal constant AUTHORIZE_ACTOR = 0x01;
    uint8 internal constant REVOKE_ACTOR = 0x02;

    bytes4 internal constant TRANSFER = bytes4(keccak256("transfer(address,uint256)"));
    uint40 internal constant MONTH = 30 days;

    PolicyManager.PolicyBinding internal lastBinding;

    function setUp() public override {
        super.setUp();
        vm.warp(1_700_000_000);

        manager = new PolicyManager(address(keystore));
        policy = new SessionPolicy(address(manager));
        token = new ExtMockERC20();
    }

    // ── Single-account external pull ──

    function test_executeFor_happyPath() public {
        address account = _optIn(bytes32(uint256(1)), 100e6, MONTH);

        vm.prank(provider);
        manager.executeFor(lastBinding, _pull(30e6));

        assertEq(token.balanceOf(recipient), 30e6);
        assertEq(token.balanceOf(account), 1_000e6 - 30e6);
    }

    function test_executeFor_revertsForUnauthorizedCaller() public {
        address account = _optIn(bytes32(uint256(1)), 100e6, MONTH);

        // A different external address was never authorized by the account → not a live actor of it.
        address stranger = address(0xBAD);
        vm.expectRevert(abi.encodeWithSelector(PolicyManager.InvalidActor.selector, bytes32(bytes20(stranger))));
        vm.prank(stranger);
        manager.executeFor(lastBinding, _pull(1));
    }

    function test_executeFor_revertsWhenManagerNotGated() public {
        // The account authorized the provider, but pointed it at a *different* manager. This manager must refuse,
        // since the external path has no protocol routing to lean on.
        address account = _createAccount(bytes32(uint256(1)));
        (PolicyManager.PolicyBinding memory binding, bytes32 commitment) = _binding(account, 7, 100e6, MONTH);
        _authorizeProvider(account, address(0xDEAD), commitment); // wrong manager

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.NoActivePolicy.selector, bytes32(bytes20(provider))));
        vm.prank(provider);
        manager.executeFor(binding, _pull(1));
    }

    function test_executeFor_revertsWhenCommitmentZero() public {
        // The account gated the provider to *this* manager but with a zero (empty) commitment. The manager-match
        // passes, but the live commitment read resolves to zero, so there is no binding to enforce.
        address account = _createAccount(bytes32(uint256(1)));
        (PolicyManager.PolicyBinding memory binding,) = _binding(account, 1, 100e6, MONTH);
        _authorizeProvider(account, address(manager), bytes32(0));

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.NoActivePolicy.selector, bytes32(bytes20(provider))));
        vm.prank(provider);
        manager.executeFor(binding, _pull(1));
    }

    function test_executeFor_revertsAfterRevoke() public {
        address account = _optIn(bytes32(uint256(1)), 100e6, MONTH);

        _revokeProvider(account);

        // A revoked provider is no longer a live actor of the account.
        vm.expectRevert(abi.encodeWithSelector(PolicyManager.InvalidActor.selector, bytes32(bytes20(provider))));
        vm.prank(provider);
        manager.executeFor(lastBinding, _pull(1));
    }

    function test_executeFor_revertsWhenActorExpired() public {
        // External path has no protocol auth, so liveness must be enforced in the manager; an expired actor is
        // rejected as InvalidActor.
        uint48 expiry = uint48(block.timestamp + 1 days);
        address account = _optInWithExpiry(bytes32(uint256(1)), 100e6, MONTH, expiry);

        vm.warp(uint256(expiry) + 1);
        vm.expectRevert(abi.encodeWithSelector(PolicyManager.InvalidActor.selector, bytes32(bytes20(provider))));
        vm.prank(provider);
        manager.executeFor(lastBinding, _pull(1));
    }

    function test_executeFor_revertsForNonExternalPullActor() public {
        // The provider is a live, policy-gated actor of the account, correctly gated to this manager with a matching
        // commitment — but it was provisioned with a *signing* authenticator, not EXTERNAL_POLICY_AUTHENTICATOR. Such
        // a native key must act through the protocol-authenticated path, never the auth-less external pull.
        address account = _createAccount(bytes32(uint256(1)));
        (PolicyManager.PolicyBinding memory binding, bytes32 commitment) = _binding(account, 1, 100e6, MONTH);
        _authorizeProviderWithAuthenticator(account, address(k1Authenticator), address(manager), commitment, 0);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.InvalidActor.selector, bytes32(bytes20(provider))));
        vm.prank(provider);
        manager.executeFor(binding, _pull(1));
    }

    function test_executeFor_revertsOverBudget() public {
        address account = _optIn(bytes32(uint256(1)), 50e6, MONTH);

        vm.prank(provider);
        manager.executeFor(lastBinding, _pull(50e6));

        // A second pull this month would exceed the $50 cap.
        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, 51e6, 50e6));
        vm.prank(provider);
        manager.executeFor(lastBinding, _pull(1e6));
    }

    function test_executeFor_refreshesNextMonth() public {
        address account = _optIn(bytes32(uint256(1)), 50e6, MONTH);

        vm.prank(provider);
        manager.executeFor(lastBinding, _pull(50e6));

        vm.warp(block.timestamp + MONTH);
        vm.prank(provider);
        manager.executeFor(lastBinding, _pull(40e6));

        assertEq(token.balanceOf(recipient), 90e6);
    }

    // ── Cross-account best-effort batch ──

    function test_executeForMany_bestEffort_isolatesFailures() public {
        // Three subscribers; the middle one opts in then revokes, so its pull reverts (InvalidActor) and must be
        // skipped without blocking the other two.
        address a1 = _optIn(bytes32(uint256(1)), 100e6, MONTH);
        address a2 = _optIn(bytes32(uint256(2)), 100e6, MONTH);
        _revokeProvider(a2);
        address a3 = _optIn(bytes32(uint256(3)), 100e6, MONTH);

        (PolicyManager.PolicyBinding memory b1,) = _binding(a1, 1, 100e6, MONTH);
        (PolicyManager.PolicyBinding memory b2,) = _binding(a2, 2, 100e6, MONTH);
        (PolicyManager.PolicyBinding memory b3,) = _binding(a3, 3, 100e6, MONTH);
        PolicyManager.PolicyBinding[] memory bindings = new PolicyManager.PolicyBinding[](3);
        bindings[0] = b1;
        bindings[1] = b2;
        bindings[2] = b3;
        bytes[] memory data = new bytes[](3);
        data[0] = _pull(10e6);
        data[1] = _pull(10e6);
        data[2] = _pull(20e6);

        vm.expectEmit(true, true, true, false);
        emit PolicyManager.ExecutionSkipped(a2, address(policy), bytes32(bytes20(provider)));

        vm.prank(provider);
        bool[] memory results = manager.executeForMany(bindings, data);

        assertTrue(results[0]);
        assertFalse(results[1]);
        assertTrue(results[2]);
        // a1 and a3 settled; a2 was skipped entirely.
        assertEq(token.balanceOf(recipient), 30e6);
        assertEq(token.balanceOf(a2), 1_000e6);
    }

    function test_executeFor_revertsWhenCommitmentBelongsToAnotherAccount() public {
        // Victim opts the provider in; commitment is authorized with binding.account == victim.
        address victim = _optIn(bytes32(uint256(1)), 100e6, MONTH);
        (, bytes32 victimCommitment) = _binding(victim, 1, 100e6, MONTH);

        // Attacker points its OWN actor (actorId = bytes20(provider)) at the victim's opaque commitment + this
        // manager. Keystore stores the commitment verbatim, so nothing stops this registration.
        address attacker = _createAccount(bytes32(uint256(2)));
        _authorizeProvider(attacker, address(manager), victimCommitment);

        // Driving via a binding that names the attacker cannot recompute to the victim's commitment (preimage
        // includes account), so the manager rejects.
        (PolicyManager.PolicyBinding memory attackerBinding,) = _binding(attacker, 2, 100e6, MONTH);
        bytes32 actual = manager.commitmentOf(attackerBinding);
        vm.expectRevert(
            abi.encodeWithSelector(PolicyManager.BindingCommitmentMismatch.selector, victimCommitment, actual)
        );
        vm.prank(provider);
        manager.executeFor(attackerBinding, _pull(10e6));

        // Nothing moved: the attack reverted, so the victim's shared spend counter and balances are untouched.
        assertEq(token.balanceOf(recipient), 0);
        SessionPolicy.TokenLimit memory victimLimit =
            SessionPolicy.TokenLimit({token: address(token), limit: 100e6, period: MONTH});
        assertEq(policy.getCurrentSpend(victimCommitment, victimLimit).spend, 0);
    }

    function test_executeForMany_revertsOnLengthMismatch() public {
        PolicyManager.PolicyBinding[] memory bindings = new PolicyManager.PolicyBinding[](2);
        bytes[] memory data = new bytes[](1);
        vm.expectRevert(PolicyManager.LengthMismatch.selector);
        vm.prank(provider);
        manager.executeForMany(bindings, data);
    }

    function test_enforceExternalSelf_revertsForExternalCaller() public {
        // The self-call boundary used by the batch must reject any caller other than the manager itself.
        PolicyManager.PolicyBinding memory binding;
        binding.account = address(0x1);
        vm.expectRevert(PolicyManager.OnlySelf.selector);
        vm.prank(provider);
        manager.enforceExternalSelf(binding, bytes32(bytes20(provider)), _pull(1), provider);
    }

    // ── Helpers ──

    function _pull(uint256 amount) internal view returns (bytes memory) {
        return abi.encode(
            SessionPolicy.Action({
                target: address(token), value: 0, data: abi.encodeCall(ExtMockERC20.transfer, (recipient, amount))
            })
        );
    }

    /// @dev SessionPolicy config: `transfer` only on `token`, with a USDC-style recurring spend limit.
    /// @dev `public` and invoked via `this._config(...)` from `_binding` so its nested-struct abi.encode stays in its
    ///      own stack frame; inlining it merges that frame into every test and trips a via_ir stack-too-deep.
    function _config(uint256 limit, uint40 period) public view returns (bytes memory) {
        SessionPolicy.TokenLimit[] memory limits = new SessionPolicy.TokenLimit[](1);
        limits[0] = SessionPolicy.TokenLimit({token: address(token), limit: limit, period: period});
        SessionPolicy.SelectorRule[] memory rules = new SessionPolicy.SelectorRule[](1);
        rules[0] = SessionPolicy.SelectorRule({selector: ExtMockERC20.transfer.selector, recipients: new address[](0)});
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = SessionPolicy.CallScope({target: address(token), selectorRules: rules});
        return abi.encode(SessionPolicy.Config({tokenLimits: limits, callScopes: scopes}));
    }

    function _binding(address account, uint256 salt, uint256 limit, uint40 period)
        internal
        view
        returns (PolicyManager.PolicyBinding memory binding, bytes32 commitment)
    {
        binding = PolicyManager.PolicyBinding({
            account: account,
            policy: address(policy),
            policyConfig: this._config(limit, period),
            validAfter: 0,
            validUntil: 0,
            salt: salt
        });
        commitment = manager.commitmentOf(binding);
    }

    /// @dev Full opt-in for one subscriber: create the account, mint it tokens, and authorize the provider as an
    ///      external-policy actor gated to this manager with the binding commitment.
    function _optIn(bytes32 accountSalt, uint256 limit, uint40 period) internal returns (address account) {
        return _optInWithExpiry(accountSalt, limit, period, 0);
    }

    function _optInWithExpiry(bytes32 accountSalt, uint256 limit, uint40 period, uint48 expiry)
        internal
        returns (address account)
    {
        account = _createAccount(accountSalt);
        (PolicyManager.PolicyBinding memory binding, bytes32 commitment) =
            _binding(account, uint256(accountSalt), limit, period);
        lastBinding = binding;
        _authorizeProvider(account, address(manager), commitment, expiry);
    }

    function _createAccount(bytes32 salt) internal returns (address account) {
        Keystore.InitialActor memory root = Keystore.InitialActor({
            actorId: bytes32(bytes20(vm.addr(ROOT_PK))),
            authenticator: address(k1Authenticator),
            scope: 0,
            policyData: ""
        });
        Keystore.InitialActor memory mgr = Keystore.InitialActor({
            actorId: bytes32(bytes20(address(manager))), authenticator: TRUSTED_EXECUTOR, scope: 0, policyData: ""
        });
        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](2);
        (actors[0], actors[1]) = root.actorId < mgr.actorId ? (root, mgr) : (mgr, root);

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        account = keystore.createAccount(salt, bytecode, actors);
        token.mint(account, 1_000e6);
    }

    /// @dev Authorize the provider as an external-policy actor: no direct authority, gated to `policyManager` with
    ///      `commitment`. The actorId is the provider's own address.
    function _authorizeProvider(address account, address policyManager, bytes32 commitment) internal {
        _authorizeProvider(account, policyManager, commitment, 0);
    }

    function _authorizeProvider(address account, address policyManager, bytes32 commitment, uint48 expiry) internal {
        _authorizeProviderWithAuthenticator(account, EXTERNAL_POLICY_AUTHENTICATOR, policyManager, commitment, expiry);
    }

    /// @dev Authorize the provider actor with an arbitrary `authenticator` (an external-pull actor MUST use
    ///      {EXTERNAL_POLICY_AUTHENTICATOR}; used by tests to provision a non-external-pull actor and assert the
    ///      manager rejects it on the external path).
    function _authorizeProviderWithAuthenticator(
        address account,
        address authenticator,
        address policyManager,
        bytes32 commitment,
        uint48 expiry
    ) internal {
        Keystore.ActorConfig memory cfg = Keystore.ActorConfig({
            authenticator: authenticator, scope: SCOPE_POLICY, expiry: expiry
        });
        Keystore.ActorChange[] memory changes = new Keystore.ActorChange[](1);
        changes[0] = Keystore.ActorChange({
            actorId: bytes32(bytes20(provider)),
            changeType: AUTHORIZE_ACTOR,
            data: abi.encode(cfg, abi.encodePacked(policyManager, commitment))
        });
        _applyAsRoot(account, changes);
    }

    function _revokeProvider(address account) internal {
        Keystore.ActorChange[] memory changes = new Keystore.ActorChange[](1);
        changes[0] = Keystore.ActorChange({actorId: bytes32(bytes20(provider)), changeType: REVOKE_ACTOR, data: ""});
        _applyAsRoot(account, changes);
    }

    function _applyAsRoot(address account, Keystore.ActorChange[] memory changes) internal {
        uint64 chainId = uint64(block.chainid);
        uint64 sequence = keystore.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, chainId, sequence, changes);
        keystore.applySignedActorChanges(account, chainId, changes, _buildK1Auth(ROOT_PK, digest));
    }
}
