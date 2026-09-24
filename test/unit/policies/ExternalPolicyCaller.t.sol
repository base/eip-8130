// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "../../../src/Keystore.sol";
import {Scopes} from "../../../src/libraries/Scopes.sol";

import {Policy, EXTERNAL_POLICY_AUTHENTICATOR} from "../../../src/policies/Policy.sol";
import {PolicyBinding} from "../../../src/policies/PolicyBinding.sol";
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
///         via {Policy.executeFor} / {executeForMany}. Identity is the caller itself
///         (`actorId == ActorId.fromAddress(msg.sender)`); the provider actor is registered with `EXTERNAL_POLICY_AUTHENTICATOR`
///         so it can only act through the manager, never directly.
contract ExternalPolicyCallerTest is KeystoreTest {
    SessionPolicy internal policy;
    ExtMockERC20 internal token;

    address internal provider = address(0x9405); // the external caller (subscription provider)
    address internal recipient = address(0x5EE);

    uint256 internal constant ROOT_PK = 0xA11CE;
    uint16 internal constant SCOPE_OPERATOR = Scopes.OPERATOR;
    uint16 internal constant SCOPE_POLICY = Scopes.POLICY;

    bytes4 internal constant TRANSFER = bytes4(keccak256("transfer(address,uint256)"));
    uint40 internal constant MONTH = 30 days;

    PolicyBinding internal lastBinding;

    function setUp() public override {
        super.setUp();
        vm.warp(1_700_000_000);

        policy = new SessionPolicy(address(keystore));
        token = new ExtMockERC20();
    }

    // ── Single-account external pull ──

    function test_executeFor_happyPath() public {
        address account = _optIn(bytes32(uint256(1)), 100e6, MONTH);

        vm.prank(provider);
        policy.executeFor(lastBinding, _pull(30e6));

        assertEq(token.balanceOf(recipient), 30e6);
        assertEq(token.balanceOf(account), 1_000e6 - 30e6);
    }

    function test_executeFor_revertsForUnauthorizedCaller() public {
        address account = _optIn(bytes32(uint256(1)), 100e6, MONTH);

        // A different external address was never authorized by the account → not a live actor of it.
        address stranger = address(0xBAD);
        vm.expectRevert(abi.encodeWithSelector(Policy.InvalidActor.selector, bytes32(uint256(uint160(stranger)))));
        vm.prank(stranger);
        policy.executeFor(lastBinding, _pull(1));
    }

    function test_executeFor_revertsWhenManagerNotGated() public {
        // The account authorized the provider, but pointed it at a *different* policy. This manager must refuse,
        // since the external path has no protocol routing to lean on.
        address account = _createAccount(bytes32(uint256(1)));
        (PolicyBinding memory binding, bytes32 commitment) = _binding(account, 7, 100e6, MONTH);
        _authorizeProvider(account, address(0xDEAD), commitment); // wrong manager

        vm.expectRevert(abi.encodeWithSelector(Policy.NoActivePolicy.selector, bytes32(uint256(uint160(provider)))));
        vm.prank(provider);
        policy.executeFor(binding, _pull(1));
    }

    function test_executeFor_revertsWhenCommitmentZero() public {
        // The account gated the provider to *this* manager but with a zero (empty) commitment. The manager-match
        // passes, but the live commitment read resolves to zero, so there is no binding to enforce.
        address account = _createAccount(bytes32(uint256(1)));
        (PolicyBinding memory binding,) = _binding(account, 1, 100e6, MONTH);
        _authorizeProvider(account, address(policy), bytes32(0));

        vm.expectRevert(abi.encodeWithSelector(Policy.NoActivePolicy.selector, bytes32(uint256(uint160(provider)))));
        vm.prank(provider);
        policy.executeFor(binding, _pull(1));
    }

    function test_executeFor_revertsAfterRevoke() public {
        address account = _optIn(bytes32(uint256(1)), 100e6, MONTH);

        _revokeProvider(account);

        // A revoked provider is no longer a live actor of the account.
        vm.expectRevert(abi.encodeWithSelector(Policy.InvalidActor.selector, bytes32(uint256(uint160(provider)))));
        vm.prank(provider);
        policy.executeFor(lastBinding, _pull(1));
    }

    function test_executeFor_revertsWhenActorExpired() public {
        // External path has no protocol auth, so liveness must be enforced in the manager; an expired actor is
        // rejected as InvalidActor.
        uint48 expiry = uint48(block.timestamp + 1 days);
        address account = _optInWithExpiry(bytes32(uint256(1)), 100e6, MONTH, expiry);

        vm.warp(uint256(expiry) + 1);
        vm.expectRevert(abi.encodeWithSelector(Policy.InvalidActor.selector, bytes32(uint256(uint160(provider)))));
        vm.prank(provider);
        policy.executeFor(lastBinding, _pull(1));
    }

    function test_executeFor_revertsForNonExternalPullActor() public {
        // The provider is a live, policy-gated actor of the account, correctly gated to this manager with a matching
        // commitment — but it was provisioned with a *signing* authenticator, not EXTERNAL_POLICY_AUTHENTICATOR. Such
        // a native key must act through the protocol-authenticated path, never the auth-less external pull.
        address account = _createAccount(bytes32(uint256(1)));
        (PolicyBinding memory binding, bytes32 commitment) = _binding(account, 1, 100e6, MONTH);
        _authorizeProviderWithAuthenticator(account, address(k1Authenticator), address(policy), commitment, 0);

        vm.expectRevert(abi.encodeWithSelector(Policy.InvalidActor.selector, bytes32(uint256(uint160(provider)))));
        vm.prank(provider);
        policy.executeFor(binding, _pull(1));
    }

    function test_executeFor_revertsOverBudget() public {
        address account = _optIn(bytes32(uint256(1)), 50e6, MONTH);

        vm.prank(provider);
        policy.executeFor(lastBinding, _pull(50e6));

        // A second pull this month would exceed the $50 cap.
        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, 51e6, 50e6));
        vm.prank(provider);
        policy.executeFor(lastBinding, _pull(1e6));
    }

    function test_executeFor_refreshesNextMonth() public {
        address account = _optIn(bytes32(uint256(1)), 50e6, MONTH);

        vm.prank(provider);
        policy.executeFor(lastBinding, _pull(50e6));

        vm.warp(block.timestamp + MONTH);
        vm.prank(provider);
        policy.executeFor(lastBinding, _pull(40e6));

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

        (PolicyBinding memory b1,) = _binding(a1, 1, 100e6, MONTH);
        (PolicyBinding memory b2,) = _binding(a2, 2, 100e6, MONTH);
        (PolicyBinding memory b3,) = _binding(a3, 3, 100e6, MONTH);
        PolicyBinding[] memory bindings = new PolicyBinding[](3);
        bindings[0] = b1;
        bindings[1] = b2;
        bindings[2] = b3;
        bytes[] memory data = new bytes[](3);
        data[0] = _pull(10e6);
        data[1] = _pull(10e6);
        data[2] = _pull(20e6);

        vm.expectEmit(true, true, true, false);
        emit Policy.ExecutionSkipped(a2, address(policy), bytes32(uint256(uint160(provider))));

        vm.prank(provider);
        bool[] memory results = policy.executeForMany(bindings, data);

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

        // Attacker points its OWN actor (actorId = ActorId.fromAddress(provider)) at the victim's opaque commitment + this
        // policy. Keystore stores the commitment verbatim, so nothing stops this registration.
        address attacker = _createAccount(bytes32(uint256(2)));
        _authorizeProvider(attacker, address(policy), victimCommitment);

        // Driving via a binding that names the attacker cannot recompute to the victim's commitment (preimage
        // includes account), so the manager rejects.
        (PolicyBinding memory attackerBinding,) = _binding(attacker, 2, 100e6, MONTH);
        bytes32 actual = policy.commitmentOf(attackerBinding);
        vm.expectRevert(abi.encodeWithSelector(Policy.BindingCommitmentMismatch.selector, victimCommitment, actual));
        vm.prank(provider);
        policy.executeFor(attackerBinding, _pull(10e6));

        // Nothing moved: the attack reverted, so the victim's shared spend counter and balances are untouched.
        assertEq(token.balanceOf(recipient), 0);
        SessionPolicy.TokenLimit memory victimLimit = SessionPolicy.TokenLimit({
            token: address(token), limit: 100e6, period: MONTH, recipients: new address[](0)
        });
        assertEq(policy.getCurrentSpend(victimCommitment, victimLimit).spend, 0);
    }

    function test_executeForMany_revertsOnLengthMismatch() public {
        PolicyBinding[] memory bindings = new PolicyBinding[](2);
        bytes[] memory data = new bytes[](1);
        vm.expectRevert(Policy.LengthMismatch.selector);
        vm.prank(provider);
        policy.executeForMany(bindings, data);
    }

    function test_enforceExternalSelf_revertsForExternalCaller() public {
        // The self-call boundary used by the batch must reject any caller other than the manager itself.
        PolicyBinding memory binding;
        binding.account = address(0x1);
        vm.expectRevert(Policy.OnlySelf.selector);
        vm.prank(provider);
        policy.enforceExternalSelf(binding, bytes32(uint256(uint160(provider))), _pull(1), provider);
    }

    // ── Helpers ──

    function _pull(uint256 amount) internal view returns (bytes memory) {
        return abi.encode(
            SessionPolicy.Action({
                target: address(token), value: 0, data: abi.encodeCall(ExtMockERC20.transfer, (recipient, amount))
            })
        );
    }

    /// @dev SessionPolicy config: a Case-1 USDC-style recurring spend limit on `token` (the limit alone authorizes
    ///      the tracked ERC-20 selectors, so no CallScope is needed).
    /// @dev `public` and invoked via `this._config(...)` from `_binding` so its nested-struct abi.encode stays in its
    ///      own stack frame; inlining it merges that frame into every test and trips a via_ir stack-too-deep.
    function _config(uint256 limit, uint40 period) public view returns (bytes memory) {
        SessionPolicy.TokenLimit[] memory limits = new SessionPolicy.TokenLimit[](1);
        limits[0] = SessionPolicy.TokenLimit({
            token: address(token), limit: limit, period: period, recipients: new address[](0)
        });
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](0);
        return abi.encode(SessionPolicy.Config({tokenLimits: limits, callScopes: scopes}));
    }

    function _binding(address account, uint256 salt, uint256 limit, uint40 period)
        internal
        view
        returns (PolicyBinding memory binding, bytes32 commitment)
    {
        binding = PolicyBinding({
            account: account,
            policy: address(policy),
            policyConfig: this._config(limit, period),
            validAfter: 0,
            validUntil: 0,
            salt: salt,
            transformer: address(0)
        });
        commitment = policy.commitmentOf(binding);
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
        (PolicyBinding memory binding, bytes32 commitment) = _binding(account, uint256(accountSalt), limit, period);
        lastBinding = binding;
        _authorizeProvider(account, address(policy), commitment, expiry);
    }

    function _createAccount(bytes32 salt) internal returns (address account) {
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
        // A zero expiry (the old "no expiry") maps to UNBOUNDED, signed by the root owner.
        uint48 grant = expiry == 0 ? UNBOUNDED : expiry;
        _applyLocal(
            ROOT_PK,
            account,
            _one(
                _authorizeChange(
                    bytes32(uint256(uint160(provider))),
                    authenticator,
                    SCOPE_POLICY,
                    grant,
                    abi.encodePacked(policyManager, commitment)
                )
            )
        );
    }

    function _revokeProvider(address account) internal {
        // A bare admin-signed revoke; it clears the slot here (no outstanding replayable grant to retire).
        _revokeActor(account, ROOT_PK, bytes32(uint256(uint160(provider))));
    }
}
