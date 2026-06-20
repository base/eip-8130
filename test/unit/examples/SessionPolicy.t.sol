// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IAccountConfiguration} from "../../../src/interfaces/IAccountConfiguration.sol";
import {ITransactionContext, TX_CONTEXT_ADDRESS} from "../../../src/interfaces/ITransactionContext.sol";
import {EXTERNAL_CALLER_AUTHENTICATOR} from "../../../src/accounts/DefaultAccount.sol";

import {PolicyManager} from "../../../src/examples/policies/PolicyManager.sol";
import {SessionPolicy} from "../../../src/examples/policies/SessionPolicy.sol";
import {RecurringAllowance} from "../../../src/examples/policies/RecurringAllowance.sol";

import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract SessionMockERC20 {
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

contract SessionMockTarget {
    uint256 public value;

    function setValue(uint256 v) external {
        value = v;
    }

    function other(uint256 v) external {
        value = v;
    }

    function adminOnly(uint256 v) external {
        value = v;
    }
}

/// @notice Exercises the unified {SessionPolicy}: target allowlist, per-target selector rules, recipient
///         allowlists, per-token recurring/one-time spend limits, native-ETH limits, and the atomic
///         multi-dimension check on a single call.
contract SessionPolicyTest is AccountConfigurationTest {
    PolicyManager internal manager;
    SessionPolicy internal policy;
    SessionMockERC20 internal token;
    SessionMockTarget internal target;

    address internal account;
    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);
    address internal mallory = address(0xBAD);

    uint256 internal constant ROOT_PK = 0xA11CE;
    uint8 internal constant SCOPE_SENDER = 0x02;
    uint8 internal constant POLICY_GATED = 0x01;
    uint8 internal constant AUTHORIZE_ACTOR = 0x01;

    bytes4 internal constant TRANSFER = bytes4(keccak256("transfer(address,uint256)"));
    uint40 internal constant WEEK = 7 days;

    uint256 internal saltNonce;

    function setUp() public override {
        super.setUp();
        vm.warp(1_700_000_000);

        manager = new PolicyManager(address(accountConfiguration));
        policy = new SessionPolicy(address(manager));
        token = new SessionMockERC20();
        target = new SessionMockTarget();

        account = _createAccountWithRootAndManager();
        token.mint(account, 1_000_000e18);
        vm.deal(account, 100 ether);
    }

    // ── Target gating ──

    function test_target_allowsListedTarget() public {
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = _anySelectorScope(address(target));
        bytes32 actorId = _install(_config(_noLimits(), scopes));

        _execute(actorId, address(target), 0, abi.encodeCall(SessionMockTarget.setValue, (42)));
        assertEq(target.value(), 42);
    }

    function test_target_revertsUnlistedTarget() public {
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = _anySelectorScope(address(target));
        bytes32 actorId = _install(_config(_noLimits(), scopes));

        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.TargetNotAllowed.selector, address(token)));
        vm.prank(account);
        manager.execute(
            address(policy), _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 1)))
        );
    }

    // ── Selector gating ──

    function test_selector_allowsListedSelector() public {
        SessionPolicy.SelectorRule[] memory rules = new SessionPolicy.SelectorRule[](1);
        rules[0] =
            SessionPolicy.SelectorRule({selector: SessionMockTarget.setValue.selector, recipients: _noRecipients()});
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = SessionPolicy.CallScope({target: address(target), selectorRules: rules});
        bytes32 actorId = _install(_config(_noLimits(), scopes));

        _execute(actorId, address(target), 0, abi.encodeCall(SessionMockTarget.setValue, (7)));
        assertEq(target.value(), 7);
    }

    function test_selector_revertsUnlistedSelector() public {
        SessionPolicy.SelectorRule[] memory rules = new SessionPolicy.SelectorRule[](1);
        rules[0] =
            SessionPolicy.SelectorRule({selector: SessionMockTarget.setValue.selector, recipients: _noRecipients()});
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = SessionPolicy.CallScope({target: address(target), selectorRules: rules});
        bytes32 actorId = _install(_config(_noLimits(), scopes));

        _mockActingActor(actorId);
        vm.expectRevert(
            abi.encodeWithSelector(
                SessionPolicy.SelectorNotAllowed.selector, address(target), SessionMockTarget.other.selector
            )
        );
        vm.prank(account);
        manager.execute(address(policy), _action(address(target), 0, abi.encodeCall(SessionMockTarget.other, (1))));
    }

    // ── Recipient gating ──

    function test_recipient_allowsListedRecipient() public {
        address[] memory recipients = new address[](1);
        recipients[0] = bob;
        bytes32 actorId = _install(_config(_noLimits(), _erc20Scope(address(token), recipients)));

        _execute(actorId, address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 100e18)));
        assertEq(token.balanceOf(bob), 100e18);
    }

    function test_recipient_revertsUnlistedRecipient() public {
        address[] memory recipients = new address[](1);
        recipients[0] = bob;
        bytes32 actorId = _install(_config(_noLimits(), _erc20Scope(address(token), recipients)));

        _mockActingActor(actorId);
        vm.expectRevert(
            abi.encodeWithSelector(SessionPolicy.RecipientNotAllowed.selector, address(token), TRANSFER, mallory)
        );
        vm.prank(account);
        manager.execute(
            address(policy), _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (mallory, 1)))
        );
    }

    // ── Recurring spend limit ──

    function test_recurringLimit_withinAllowance() public {
        bytes32 actorId =
            _install(_config(_limit(address(token), 500e18, WEEK), _erc20Scope(address(token), _noRecipients())));

        _execute(actorId, address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 300e18)));
        assertEq(token.balanceOf(bob), 300e18);
    }

    function test_recurringLimit_revertsWhenExceeded() public {
        bytes32 actorId =
            _install(_config(_limit(address(token), 500e18, WEEK), _erc20Scope(address(token), _noRecipients())));
        _mockActingActor(actorId);

        vm.prank(account);
        manager.execute(
            address(policy), _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 300e18)))
        );

        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, 600e18, 500e18));
        vm.prank(account);
        manager.execute(
            address(policy), _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 300e18)))
        );
    }

    function test_recurringLimit_resetsNextPeriod() public {
        bytes32 actorId =
            _install(_config(_limit(address(token), 500e18, WEEK), _erc20Scope(address(token), _noRecipients())));
        _mockActingActor(actorId);

        vm.prank(account);
        manager.execute(
            address(policy), _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 500e18)))
        );

        // Crossing exactly one aligned period refreshes the budget (window is epoch-0 aligned).
        vm.warp(block.timestamp + WEEK);
        vm.prank(account);
        manager.execute(
            address(policy), _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 400e18)))
        );

        assertEq(token.balanceOf(bob), 900e18);
    }

    // ── One-time spend limit (period == 0): cumulative, never resets ──

    function test_oneTimeLimit_accumulatesAcrossPeriods() public {
        bytes32 actorId =
            _install(_config(_limit(address(token), 500e18, 0), _erc20Scope(address(token), _noRecipients())));
        _mockActingActor(actorId);

        vm.prank(account);
        manager.execute(
            address(policy), _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 300e18)))
        );

        // Even a year later the one-time cap does not refresh.
        vm.warp(block.timestamp + 365 days);
        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, 600e18, 500e18));
        vm.prank(account);
        manager.execute(
            address(policy), _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 300e18)))
        );
    }

    // ── Native-ETH spend limit ──

    function test_nativeLimit_consumesCallValue() public {
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = _anySelectorScope(bob);
        bytes32 actorId = _install(_config(_limit(address(0), 1 ether, WEEK), scopes));
        _mockActingActor(actorId);

        vm.prank(account);
        manager.execute(address(policy), _action(bob, 0.6 ether, ""));
        assertEq(bob.balance, 0.6 ether);

        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, 1.2 ether, 1 ether));
        vm.prank(account);
        manager.execute(address(policy), _action(bob, 0.6 ether, ""));
    }

    // ── Atomic multi-dimension enforcement on a single call ──

    function test_multiDimension_passesAllAtOnce() public {
        address[] memory recipients = new address[](1);
        recipients[0] = bob;
        bytes32 actorId =
            _install(_config(_limit(address(token), 500e18, WEEK), _erc20Scope(address(token), recipients)));

        // target + selector + recipient + within-limit all satisfied in one call.
        _execute(actorId, address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 250e18)));
        assertEq(token.balanceOf(bob), 250e18);
    }

    function test_multiDimension_recipientFailsEvenWithinLimit() public {
        address[] memory recipients = new address[](1);
        recipients[0] = bob;
        bytes32 actorId =
            _install(_config(_limit(address(token), 500e18, WEEK), _erc20Scope(address(token), recipients)));

        // Amount is within the limit, but mallory isn't an allowed recipient — the whole call is rejected.
        _mockActingActor(actorId);
        vm.expectRevert(
            abi.encodeWithSelector(SessionPolicy.RecipientNotAllowed.selector, address(token), TRANSFER, mallory)
        );
        vm.prank(account);
        manager.execute(
            address(policy), _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (mallory, 1)))
        );
    }

    // ── Worked example ──
    //
    // A single session key that: (1) has full, uncapped access to one ERC-20 (the "MyApp" token); (2) may spend at
    // most $5 of USDC per month; and (3) may call the MyApp app contract as much as it wants, but only through two
    // chosen selectors. This is the example documented in the policies README.

    function test_workedExample_fullTokenAccess_monthlyUsdc_appSelectors() public {
        // A second ERC-20 plays the role of USDC (6 decimals); `token` (minted in setUp) is the MyApp token.
        SessionMockERC20 usdc = new SessionMockERC20();
        usdc.mint(account, 1_000e6);
        uint40 monthPeriod = 30 days;
        uint256 fiveUsdc = 5e6; // $5 at 6 decimals

        // Spend limits: only USDC ($5/month). The MyApp token has no entry, so its transfers are uncapped.
        SessionPolicy.TokenLimit[] memory limits = new SessionPolicy.TokenLimit[](1);
        limits[0] = SessionPolicy.TokenLimit({token: address(usdc), limit: fiveUsdc, period: monthPeriod});

        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](3);
        // (a) MyApp token: full access — any selector, and no spend cap (no TokenLimit above).
        scopes[0] = _anySelectorScope(address(token));
        // (b) USDC: transfer only, so the $5/month cap can't be sidestepped by another selector.
        SessionPolicy.SelectorRule[] memory usdcRules = new SessionPolicy.SelectorRule[](1);
        usdcRules[0] = SessionPolicy.SelectorRule({selector: TRANSFER, recipients: _noRecipients()});
        scopes[1] = SessionPolicy.CallScope({target: address(usdc), selectorRules: usdcRules});
        // (c) MyApp app contract: two chosen selectors, unlimited calls.
        SessionPolicy.SelectorRule[] memory appRules = new SessionPolicy.SelectorRule[](2);
        appRules[0] =
            SessionPolicy.SelectorRule({selector: SessionMockTarget.setValue.selector, recipients: _noRecipients()});
        appRules[1] =
            SessionPolicy.SelectorRule({selector: SessionMockTarget.other.selector, recipients: _noRecipients()});
        scopes[2] = SessionPolicy.CallScope({target: address(target), selectorRules: appRules});

        bytes32 actorId = _install(_config(limits, scopes));

        // Uncapped MyApp token transfer.
        _execute(actorId, address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 750_000e18)));
        assertEq(token.balanceOf(bob), 750_000e18);

        // USDC within the monthly cap.
        _execute(actorId, address(usdc), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 3e6)));
        assertEq(usdc.balanceOf(bob), 3e6);

        // MyApp app calls, both selectors, repeatedly.
        _execute(actorId, address(target), 0, abi.encodeCall(SessionMockTarget.setValue, (1)));
        _execute(actorId, address(target), 0, abi.encodeCall(SessionMockTarget.other, (2)));
        _execute(actorId, address(target), 0, abi.encodeCall(SessionMockTarget.setValue, (3)));
        assertEq(target.value(), 3);

        // A further $3 USDC this month would total $6 > $5 → rejected.
        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, 6e6, fiveUsdc));
        vm.prank(account);
        manager.execute(
            address(policy), _action(address(usdc), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 3e6)))
        );

        // A selector outside the two chosen ones on MyApp → rejected.
        _mockActingActor(actorId);
        vm.expectRevert(
            abi.encodeWithSelector(
                SessionPolicy.SelectorNotAllowed.selector, address(target), SessionMockTarget.adminOnly.selector
            )
        );
        vm.prank(account);
        manager.execute(address(policy), _action(address(target), 0, abi.encodeCall(SessionMockTarget.adminOnly, (9))));

        // Next month: the USDC budget refreshes back to $5.
        vm.warp(block.timestamp + monthPeriod);
        _execute(actorId, address(usdc), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 4e6)));
        assertEq(usdc.balanceOf(bob), 3e6 + 4e6);
    }

    // ── Install guards ──

    function test_install_revertsRecipientRuleOnUnsupportedSelector() public {
        address[] memory recipients = new address[](1);
        recipients[0] = bob;
        // A recipient allowlist attached to a non-ERC20 selector cannot be enforced → reject at install.
        SessionPolicy.SelectorRule[] memory rules = new SessionPolicy.SelectorRule[](1);
        rules[0] = SessionPolicy.SelectorRule({selector: SessionMockTarget.setValue.selector, recipients: recipients});
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = SessionPolicy.CallScope({target: address(target), selectorRules: rules});

        (bytes32 actorId, PolicyManager.PolicyBinding memory binding) = _prepareBinding(_config(_noLimits(), scopes));
        vm.expectRevert(
            abi.encodeWithSelector(
                SessionPolicy.RecipientRuleUnsupportedSelector.selector, SessionMockTarget.setValue.selector
            )
        );
        vm.prank(account);
        manager.install(actorId, binding);
    }

    function test_install_revertsZeroLimit() public {
        (bytes32 actorId, PolicyManager.PolicyBinding memory binding) =
            _prepareBinding(_config(_limit(address(token), 0, WEEK), _erc20Scope(address(token), _noRecipients())));
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.ZeroLimit.selector, address(token)));
        vm.prank(account);
        manager.install(actorId, binding);
    }

    function test_install_revertsLimitTooLarge() public {
        uint256 tooLarge = uint256(type(uint160).max) + 1;
        (bytes32 actorId, PolicyManager.PolicyBinding memory binding) = _prepareBinding(
            _config(_limit(address(token), tooLarge, WEEK), _erc20Scope(address(token), _noRecipients()))
        );
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.LimitTooLarge.selector, address(token), tooLarge));
        vm.prank(account);
        manager.install(actorId, binding);
    }

    // ── Helpers ──

    function _mockActingActor(bytes32 actorId) internal {
        vm.mockCall(
            TX_CONTEXT_ADDRESS,
            abi.encodeWithSelector(ITransactionContext.getTransactionSenderActorId.selector),
            abi.encode(actorId)
        );
    }

    /// @dev Mock the acting actor, then drive a successful execute as the account.
    function _execute(bytes32 actorId, address t, uint256 value, bytes memory data) internal {
        _mockActingActor(actorId);
        vm.prank(account);
        manager.execute(address(policy), _action(t, value, data));
    }

    function _action(address t, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        return abi.encode(SessionPolicy.Action({target: t, value: value, data: data}));
    }

    function _config(SessionPolicy.TokenLimit[] memory limits, SessionPolicy.CallScope[] memory scopes)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(SessionPolicy.Config({tokenLimits: limits, callScopes: scopes}));
    }

    function _noLimits() internal pure returns (SessionPolicy.TokenLimit[] memory) {
        return new SessionPolicy.TokenLimit[](0);
    }

    function _limit(address tkn, uint256 lim, uint40 period)
        internal
        pure
        returns (SessionPolicy.TokenLimit[] memory limits)
    {
        limits = new SessionPolicy.TokenLimit[](1);
        limits[0] = SessionPolicy.TokenLimit({token: tkn, limit: lim, period: period});
    }

    function _noRecipients() internal pure returns (address[] memory) {
        return new address[](0);
    }

    function _anySelectorScope(address t) internal pure returns (SessionPolicy.CallScope memory) {
        return SessionPolicy.CallScope({target: t, selectorRules: new SessionPolicy.SelectorRule[](0)});
    }

    /// @dev A single call scope on `tkn` allowing ERC-20 `transfer` with the given recipient allowlist.
    function _erc20Scope(address tkn, address[] memory recipients)
        internal
        pure
        returns (SessionPolicy.CallScope[] memory scopes)
    {
        SessionPolicy.SelectorRule[] memory rules = new SessionPolicy.SelectorRule[](1);
        rules[0] = SessionPolicy.SelectorRule({selector: TRANSFER, recipients: recipients});
        scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = SessionPolicy.CallScope({target: tkn, selectorRules: rules});
    }

    function _createAccountWithRootAndManager() internal returns (address) {
        IAccountConfiguration.InitialActor memory root = IAccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(vm.addr(ROOT_PK))), authenticator: address(k1Authenticator)
        });
        IAccountConfiguration.InitialActor memory mgr = IAccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(address(manager))), authenticator: EXTERNAL_CALLER_AUTHENTICATOR
        });

        IAccountConfiguration.InitialActor[] memory actors = new IAccountConfiguration.InitialActor[](2);
        (actors[0], actors[1]) = root.actorId < mgr.actorId ? (root, mgr) : (mgr, root);

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        return accountConfiguration.createAccount(bytes32(0), bytecode, actors);
    }

    /// @dev Authorize a fresh session-key actor gated to the manager committing to `policyConfig`, then install
    ///      the binding at the manager. Returns the actorId.
    function _install(bytes memory policyConfig) internal returns (bytes32 actorId) {
        PolicyManager.PolicyBinding memory binding;
        (actorId, binding) = _prepareBinding(policyConfig);
        vm.prank(account);
        manager.install(actorId, binding);
    }

    /// @dev Authorize a fresh session-key actor committing to `policyConfig` and return the (actorId, binding) for an
    ///      install call. Stops short of {PolicyManager.install} so a test can `vm.expectRevert` immediately before it
    ///      (e.g. for the onInstall config-validation guards).
    function _prepareBinding(bytes memory policyConfig)
        internal
        returns (bytes32 actorId, PolicyManager.PolicyBinding memory binding)
    {
        actorId = keccak256(abi.encode("session", saltNonce++));
        binding = PolicyManager.PolicyBinding({
            account: account,
            policy: address(policy),
            policyConfig: policyConfig,
            validAfter: 0,
            validUntil: 0,
            salt: saltNonce
        });
        bytes32 commitment = manager.commitmentOf(binding);

        IAccountConfiguration.ActorConfig memory cfg = IAccountConfiguration.ActorConfig({
            authenticator: address(k1Authenticator), scope: SCOPE_SENDER, expiry: 0, policyType: POLICY_GATED
        });
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: actorId,
            changeType: AUTHORIZE_ACTOR,
            data: abi.encode(cfg, abi.encodePacked(address(manager), commitment))
        });
        uint64 chainId = uint64(block.chainid);
        uint64 sequence = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, chainId, sequence, changes);
        accountConfiguration.applySignedActorChanges(account, chainId, changes, _buildK1Auth(ROOT_PK, digest));
    }
}
