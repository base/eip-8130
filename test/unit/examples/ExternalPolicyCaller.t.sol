// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IAccountConfiguration} from "../../../src/interfaces/IAccountConfiguration.sol";
import {EXTERNAL_CALLER_AUTHENTICATOR} from "../../../src/accounts/DefaultAccount.sol";

import {PolicyManager, EXTERNAL_POLICY_AUTHENTICATOR} from "../../../src/examples/policies/PolicyManager.sol";
import {SessionPolicy} from "../../../src/examples/policies/SessionPolicy.sol";
import {RecurringAllowance} from "../../../src/examples/policies/RecurringAllowance.sol";

import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

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
contract ExternalPolicyCallerTest is AccountConfigurationTest {
    PolicyManager internal manager;
    SessionPolicy internal policy;
    ExtMockERC20 internal token;

    address internal provider = address(0x9405); // the external caller (subscription provider)
    address internal recipient = address(0x5EE);

    uint256 internal constant ROOT_PK = 0xA11CE;
    uint8 internal constant SCOPE_SENDER = 0x02;
    uint8 internal constant POLICY_GATED = 0x01;
    uint8 internal constant AUTHORIZE_ACTOR = 0x01;
    uint8 internal constant REVOKE_ACTOR = 0x02;

    bytes4 internal constant TRANSFER = bytes4(keccak256("transfer(address,uint256)"));
    uint40 internal constant MONTH = 30 days;

    function setUp() public override {
        super.setUp();
        vm.warp(1_700_000_000);

        manager = new PolicyManager(address(accountConfiguration));
        policy = new SessionPolicy(address(manager));
        token = new ExtMockERC20();
    }

    // ── Single-account external pull ──

    function test_executeFor_happyPath() public {
        address account = _optIn(bytes32(uint256(1)), 100e6, MONTH);

        vm.prank(provider);
        manager.executeFor(account, address(policy), _pull(30e6));

        assertEq(token.balanceOf(recipient), 30e6);
        assertEq(token.balanceOf(account), 1_000e6 - 30e6);
    }

    function test_executeFor_revertsForUnauthorizedCaller() public {
        address account = _optIn(bytes32(uint256(1)), 100e6, MONTH);

        // A different external address was never authorized by the account → no manager binding for its actorId.
        address stranger = address(0xBAD);
        vm.expectRevert(abi.encodeWithSelector(PolicyManager.NoActivePolicy.selector, bytes32(bytes20(stranger))));
        vm.prank(stranger);
        manager.executeFor(account, address(policy), _pull(1));
    }

    function test_executeFor_revertsWhenManagerNotGated() public {
        // The account authorized the provider, but pointed it at a *different* manager. This manager must refuse,
        // since the external path has no protocol routing to lean on.
        address account = _createAccount(bytes32(uint256(1)));
        (PolicyManager.PolicyBinding memory binding, bytes32 commitment) = _binding(account, 7, 100e6, MONTH);
        _authorizeProvider(account, address(0xDEAD), commitment); // wrong manager

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.NoActivePolicy.selector, bytes32(bytes20(provider))));
        vm.prank(provider);
        manager.executeFor(account, address(policy), _pull(1));
        binding; // silence unused
    }

    function test_executeFor_revertsAfterRevoke() public {
        address account = _optIn(bytes32(uint256(1)), 100e6, MONTH);

        _revokeProvider(account);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.NoActivePolicy.selector, bytes32(bytes20(provider))));
        vm.prank(provider);
        manager.executeFor(account, address(policy), _pull(1));
    }

    function test_executeFor_revertsOverBudget() public {
        address account = _optIn(bytes32(uint256(1)), 50e6, MONTH);

        vm.prank(provider);
        manager.executeFor(account, address(policy), _pull(50e6));

        // A second pull this month would exceed the $50 cap.
        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, 51e6, 50e6));
        vm.prank(provider);
        manager.executeFor(account, address(policy), _pull(1e6));
    }

    function test_executeFor_refreshesNextMonth() public {
        address account = _optIn(bytes32(uint256(1)), 50e6, MONTH);

        vm.prank(provider);
        manager.executeFor(account, address(policy), _pull(50e6));

        vm.warp(block.timestamp + MONTH);
        vm.prank(provider);
        manager.executeFor(account, address(policy), _pull(40e6));

        assertEq(token.balanceOf(recipient), 90e6);
    }

    // ── Cross-account best-effort batch ──

    function test_executeForMany_bestEffort_isolatesFailures() public {
        // Three subscribers; the middle one authorized the provider but never installed the binding, so its pull
        // reverts (PolicyNotInstalled) and must be skipped without blocking the other two.
        address a1 = _optIn(bytes32(uint256(1)), 100e6, MONTH);
        address a2 = _createAccount(bytes32(uint256(2)));
        (, bytes32 c2) = _binding(a2, 2, 100e6, MONTH);
        _authorizeProvider(a2, address(manager), c2); // authorized but NOT installed
        address a3 = _optIn(bytes32(uint256(3)), 100e6, MONTH);

        address[] memory accounts = new address[](3);
        accounts[0] = a1;
        accounts[1] = a2;
        accounts[2] = a3;
        bytes[] memory data = new bytes[](3);
        data[0] = _pull(10e6);
        data[1] = _pull(10e6);
        data[2] = _pull(20e6);

        vm.expectEmit(true, true, true, false);
        emit PolicyManager.ExecutionSkipped(a2, address(policy), bytes32(bytes20(provider)));

        vm.prank(provider);
        bool[] memory results = manager.executeForMany(accounts, address(policy), data);

        assertTrue(results[0]);
        assertFalse(results[1]);
        assertTrue(results[2]);
        // a1 and a3 settled; a2 was skipped entirely.
        assertEq(token.balanceOf(recipient), 30e6);
        assertEq(token.balanceOf(a2), 1_000e6);
    }

    function test_executeFor_revertsWhenCommitmentBelongsToAnotherAccount() public {
        // Victim opts the provider in; commitment is installed with record.account == victim.
        address victim = _optIn(bytes32(uint256(1)), 100e6, MONTH);
        (, bytes32 victimCommitment) = _binding(victim, 1, 100e6, MONTH);

        // Attacker points its OWN actor (actorId = bytes20(provider)) at the victim's opaque commitment + this
        // manager. AccountConfiguration stores the commitment verbatim, so nothing stops this registration.
        address attacker = _createAccount(bytes32(uint256(2)));
        _authorizeProvider(attacker, address(manager), victimCommitment);

        // Driving the attacker account against the victim's commitment must be rejected — otherwise the attacker
        // could exhaust the victim's shared, commitment-keyed spend counter.
        vm.expectRevert(abi.encodeWithSelector(PolicyManager.CommitmentAccountMismatch.selector, victim, attacker));
        vm.prank(provider);
        manager.executeFor(attacker, address(policy), _pull(10e6));

        // Nothing moved: the attack reverted, so the victim's shared spend counter and balances are untouched.
        assertEq(token.balanceOf(recipient), 0);
        assertEq(policy.getCurrentSpend(victimCommitment, address(token)).spend, 0);
    }

    function test_executeForMany_revertsOnLengthMismatch() public {
        address[] memory accounts = new address[](2);
        bytes[] memory data = new bytes[](1);
        vm.expectRevert(PolicyManager.LengthMismatch.selector);
        vm.prank(provider);
        manager.executeForMany(accounts, address(policy), data);
    }

    function test_enforceExternalSelf_revertsForExternalCaller() public {
        // The self-call boundary used by the batch must reject any caller other than the manager itself.
        vm.expectRevert(PolicyManager.OnlySelf.selector);
        vm.prank(provider);
        manager.enforceExternalSelf(address(0x1), bytes32(bytes20(provider)), address(policy), _pull(1), provider);
    }

    // ── Helpers ──

    function _pull(uint256 amount) internal view returns (bytes memory) {
        return abi.encode(
            SessionPolicy.Action({
                target: address(token), value: 0, data: abi.encodeCall(ExtMockERC20.transfer, (recipient, amount))
            })
        );
    }

    /// @dev SessionPolicy config: allow any selector on `token`, with a USDC-style recurring spend limit.
    function _config(uint256 limit, uint40 period) internal view returns (bytes memory) {
        SessionPolicy.TokenLimit[] memory limits = new SessionPolicy.TokenLimit[](1);
        limits[0] = SessionPolicy.TokenLimit({token: address(token), limit: limit, period: period});
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] =
            SessionPolicy.CallScope({target: address(token), selectorRules: new SessionPolicy.SelectorRule[](0)});
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
            policyConfig: _config(limit, period),
            validAfter: 0,
            validUntil: 0,
            salt: salt
        });
        commitment = manager.commitmentOf(binding);
    }

    /// @dev Full opt-in for one subscriber: create the account, mint it tokens, authorize the provider as an
    ///      external-policy actor gated to this manager, and install the binding.
    function _optIn(bytes32 accountSalt, uint256 limit, uint40 period) internal returns (address account) {
        account = _createAccount(accountSalt);
        (PolicyManager.PolicyBinding memory binding, bytes32 commitment) =
            _binding(account, uint256(accountSalt), limit, period);
        _authorizeProvider(account, address(manager), commitment);
        vm.prank(account);
        manager.install(bytes32(bytes20(provider)), binding);
    }

    function _createAccount(bytes32 salt) internal returns (address account) {
        IAccountConfiguration.InitialActor memory root = IAccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(vm.addr(ROOT_PK))), authenticator: address(k1Authenticator)
        });
        IAccountConfiguration.InitialActor memory mgr = IAccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(address(manager))), authenticator: EXTERNAL_CALLER_AUTHENTICATOR
        });
        IAccountConfiguration.InitialActor[] memory actors = new IAccountConfiguration.InitialActor[](2);
        (actors[0], actors[1]) = root.actorId < mgr.actorId ? (root, mgr) : (mgr, root);

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        account = accountConfiguration.createAccount(salt, bytecode, actors);
        token.mint(account, 1_000e6);
    }

    /// @dev Authorize the provider as an external-policy actor: no direct authority, gated to `policyManager` with
    ///      `commitment`. The actorId is the provider's own address.
    function _authorizeProvider(address account, address policyManager, bytes32 commitment) internal {
        IAccountConfiguration.ActorConfig memory cfg = IAccountConfiguration.ActorConfig({
            authenticator: EXTERNAL_POLICY_AUTHENTICATOR, scope: SCOPE_SENDER, expiry: 0, policyType: POLICY_GATED
        });
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: bytes32(bytes20(provider)),
            changeType: AUTHORIZE_ACTOR,
            data: abi.encode(cfg, abi.encodePacked(policyManager, commitment))
        });
        _applyAsRoot(account, changes);
    }

    function _revokeProvider(address account) internal {
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: bytes32(bytes20(provider)), changeType: REVOKE_ACTOR, data: ""
        });
        _applyAsRoot(account, changes);
    }

    function _applyAsRoot(address account, IAccountConfiguration.ActorChange[] memory changes) internal {
        uint64 chainId = uint64(block.chainid);
        uint64 sequence = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, chainId, sequence, changes);
        accountConfiguration.applySignedActorChanges(account, chainId, changes, _buildK1Auth(ROOT_PK, digest));
    }
}
