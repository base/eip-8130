// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {ITransactionContext, TX_CONTEXT_ADDRESS} from "../../../src/interfaces/ITransactionContext.sol";
import {TRUSTED_EXECUTOR} from "../../../src/accounts/DefaultAccount.sol";

import {PolicyManager} from "../../../src/policies/PolicyManager.sol";
import {SessionPolicy} from "../../../src/policies/SessionPolicy.sol";
import {RecurringAllowance} from "../../../src/policies/RecurringAllowance.sol";

import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract SessionMockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
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
    uint8 internal constant SCOPE_SENDER = 0x01;
    uint8 internal constant SCOPE_POLICY = 0x02;
    uint8 internal constant AUTHORIZE_ACTOR = 0x01;

    bytes4 internal constant TRANSFER = bytes4(keccak256("transfer(address,uint256)"));
    uint40 internal constant WEEK = 7 days;

    uint256 internal saltNonce;
    PolicyManager.PolicyBinding internal lastBinding;

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
        manager.execute(lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 1))));
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
        manager.execute(lastBinding, _action(address(target), 0, abi.encodeCall(SessionMockTarget.other, (1))));
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
            lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (mallory, 1)))
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
            lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 300e18)))
        );

        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, 600e18, 500e18));
        vm.prank(account);
        manager.execute(
            lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 300e18)))
        );
    }

    function test_recurringLimit_resetsNextPeriod() public {
        bytes32 actorId =
            _install(_config(_limit(address(token), 500e18, WEEK), _erc20Scope(address(token), _noRecipients())));
        _mockActingActor(actorId);

        vm.prank(account);
        manager.execute(
            lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 500e18)))
        );

        // Crossing exactly one aligned period refreshes the budget (window is epoch-0 aligned).
        vm.warp(block.timestamp + WEEK);
        vm.prank(account);
        manager.execute(
            lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 400e18)))
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
            lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 300e18)))
        );

        // Even a year later the one-time cap does not refresh.
        vm.warp(block.timestamp + 365 days);
        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, 600e18, 500e18));
        vm.prank(account);
        manager.execute(
            lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 300e18)))
        );
    }

    // ── Native-ETH spend limit ──

    function test_nativeLimit_consumesCallValue() public {
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = _anySelectorScope(bob);
        bytes32 actorId = _install(_config(_limit(address(0), 1 ether, WEEK), scopes));
        _mockActingActor(actorId);

        vm.prank(account);
        manager.execute(lastBinding, _action(bob, 0.6 ether, ""));
        assertEq(bob.balance, 0.6 ether);

        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, 1.2 ether, 1 ether));
        vm.prank(account);
        manager.execute(lastBinding, _action(bob, 0.6 ether, ""));
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
            lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (mallory, 1)))
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
        manager.execute(lastBinding, _action(address(usdc), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 3e6))));

        // A selector outside the two chosen ones on MyApp → rejected.
        _mockActingActor(actorId);
        vm.expectRevert(
            abi.encodeWithSelector(
                SessionPolicy.SelectorNotAllowed.selector, address(target), SessionMockTarget.adminOnly.selector
            )
        );
        vm.prank(account);
        manager.execute(lastBinding, _action(address(target), 0, abi.encodeCall(SessionMockTarget.adminOnly, (9))));

        // Next month: the USDC budget refreshes back to $5.
        vm.warp(block.timestamp + monthPeriod);
        _execute(actorId, address(usdc), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 4e6)));
        assertEq(usdc.balanceOf(bob), 3e6 + 4e6);
    }

    // ── Config validation (at execute) ──

    function test_execute_revertsRecipientRuleOnUnsupportedSelector() public {
        address[] memory recipients = new address[](1);
        recipients[0] = bob;
        // A recipient allowlist attached to a non-ERC20 selector cannot be enforced → reject at execute.
        SessionPolicy.SelectorRule[] memory rules = new SessionPolicy.SelectorRule[](1);
        rules[0] = SessionPolicy.SelectorRule({selector: SessionMockTarget.setValue.selector, recipients: recipients});
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = SessionPolicy.CallScope({target: address(target), selectorRules: rules});

        bytes32 actorId = _authorize(_config(_noLimits(), scopes));
        _mockActingActor(actorId);
        vm.expectRevert(
            abi.encodeWithSelector(
                SessionPolicy.RecipientRuleUnsupportedSelector.selector, SessionMockTarget.setValue.selector
            )
        );
        vm.prank(account);
        manager.execute(lastBinding, _action(address(target), 0, abi.encodeCall(SessionMockTarget.setValue, (1))));
    }

    function test_execute_revertsZeroLimit() public {
        bytes32 actorId =
            _authorize(_config(_limit(address(token), 0, WEEK), _erc20Scope(address(token), _noRecipients())));
        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.ZeroLimit.selector, address(token)));
        vm.prank(account);
        manager.execute(lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 1))));
    }

    function test_execute_revertsLimitTooLarge() public {
        uint256 tooLarge = uint256(type(uint160).max) + 1;
        bytes32 actorId =
            _authorize(_config(_limit(address(token), tooLarge, WEEK), _erc20Scope(address(token), _noRecipients())));
        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.LimitTooLarge.selector, address(token), tooLarge));
        vm.prank(account);
        manager.execute(lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 1))));
    }

    function test_execute_revertsAnySelectorOnLimitedToken() public {
        // A TokenLimit only tracks transfer/transferFrom/approve; anySelector would leave other methods untracked.
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = _anySelectorScope(address(token));
        bytes32 actorId = _authorize(_config(_limit(address(token), 500e18, WEEK), scopes));
        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.AnySelectorOnLimitedToken.selector, address(token)));
        vm.prank(account);
        manager.execute(lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 1))));
    }

    function test_execute_revertsSelfTarget() public {
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = _anySelectorScope(account);
        bytes32 actorId = _authorize(_config(_noLimits(), scopes));
        _mockActingActor(actorId);
        vm.expectRevert(SessionPolicy.SelfTargetNotAllowed.selector);
        vm.prank(account);
        manager.execute(lastBinding, _action(account, 0, ""));
    }

    function test_execute_revertsDuplicateTokenLimit() public {
        SessionPolicy.TokenLimit[] memory limits = new SessionPolicy.TokenLimit[](2);
        limits[0] = SessionPolicy.TokenLimit({token: address(token), limit: 100e18, period: WEEK});
        limits[1] = SessionPolicy.TokenLimit({token: address(token), limit: 200e18, period: WEEK});
        bytes32 actorId = _authorize(_config(limits, _erc20Scope(address(token), _noRecipients())));
        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.DuplicateTokenLimit.selector, address(token)));
        vm.prank(account);
        manager.execute(lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 1))));
    }

    function test_execute_revertsDuplicateCallScope() public {
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](2);
        scopes[0] = _anySelectorScope(address(target));
        scopes[1] = _anySelectorScope(address(target));
        bytes32 actorId = _authorize(_config(_noLimits(), scopes));
        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.DuplicateCallScope.selector, address(target)));
        vm.prank(account);
        manager.execute(lastBinding, _action(address(target), 0, ""));
    }

    function test_execute_revertsDuplicateSelectorRule() public {
        SessionPolicy.SelectorRule[] memory rules = new SessionPolicy.SelectorRule[](2);
        rules[0] = SessionPolicy.SelectorRule({selector: TRANSFER, recipients: _noRecipients()});
        rules[1] = SessionPolicy.SelectorRule({selector: TRANSFER, recipients: _noRecipients()});
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = SessionPolicy.CallScope({target: address(token), selectorRules: rules});
        bytes32 actorId = _authorize(_config(_noLimits(), scopes));
        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.DuplicateSelectorRule.selector, address(token), TRANSFER));
        vm.prank(account);
        manager.execute(lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 1))));
    }

    // ── Calldata config preimage ──

    function test_execute_revertsOnPolicyConfigMismatch() public {
        // Execute must re-supply the exact committed binding; the manager recomputes the commitment.
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = _anySelectorScope(address(target));
        bytes32 actorId = _authorize(_config(_noLimits(), scopes));
        bytes32 commitment = accountConfiguration.getPolicyCommitment(account, actorId);

        PolicyManager.PolicyBinding memory wrong = lastBinding;
        wrong.policyConfig = _config(_noLimits(), _anySelectorScopes(address(token)));
        bytes32 actual = manager.commitmentOf(wrong);

        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(PolicyManager.BindingCommitmentMismatch.selector, commitment, actual));
        vm.prank(account);
        manager.execute(wrong, _action(address(target), 0, ""));
    }

    // ── Selector-length gating ──

    function test_execute_revertsMissingSelectorForShortData() public {
        // 1–3 bytes of calldata carry no usable selector, so the call is rejected rather than guessed.
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = _anySelectorScope(address(target));
        bytes32 actorId = _install(_config(_noLimits(), scopes));

        _mockActingActor(actorId);
        vm.expectRevert(SessionPolicy.MissingSelector.selector);
        vm.prank(account);
        manager.execute(lastBinding, _action(address(target), 0, hex"010203"));
    }

    function test_execute_acceptsTransferDespiteDirtySelectorWord() public {
        // ABI-encoded `transfer` packs the selector into the high 4 bytes of the first word and the address into
        // the remainder — so a raw mload into bytes4 leaves dirty low bytes. The mask must still match TRANSFER.
        bytes32 actorId =
            _install(_config(_limit(address(token), 500e18, WEEK), _erc20Scope(address(token), _noRecipients())));
        _execute(actorId, address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 1e18)));
        assertEq(token.balanceOf(bob), 1e18);
    }

    function test_execute_revertsTransferFromNotSelf() public {
        SessionPolicy.SelectorRule[] memory rules = new SessionPolicy.SelectorRule[](1);
        rules[0] = SessionPolicy.SelectorRule({selector: TRANSFER_FROM, recipients: _noRecipients()});
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = SessionPolicy.CallScope({target: address(token), selectorRules: rules});
        bytes32 actorId = _install(_config(_limit(address(token), 500e18, WEEK), scopes));

        // Approve the account to pull from mallory so the ERC-20 call would succeed absent the policy check.
        token.mint(mallory, 100e18);
        vm.prank(mallory);
        token.approve(account, 100e18);

        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.TransferFromNotSelf.selector, mallory));
        vm.prank(account);
        manager.execute(
            lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.transferFrom, (mallory, bob, 1e18)))
        );
    }

    function test_execute_allowsEmptyCalldata() public {
        // 0 bytes of calldata is a plain value call: it skips selector gating entirely.
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = _anySelectorScope(bob);
        bytes32 actorId = _install(_config(_noLimits(), scopes));

        _execute(actorId, bob, 0, "");
    }

    // ── ERC-20 spend accounting edge cases ──

    function test_execute_zeroAmountTransferSkipsSpend() public {
        // A zero-value transfer on a limited token must not touch spend accounting (the library rejects zero spends).
        (bytes32 actorId, bytes32 commitment) = _authorizeWithCommitment(
            _config(_limit(address(token), 500e18, WEEK), _erc20Scope(address(token), _noRecipients()))
        );

        _execute(actorId, address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 0)));

        assertEq(
            policy.getCurrentSpend(
                commitment, SessionPolicy.TokenLimit({token: address(token), limit: 500e18, period: WEEK})
            )
            .spend,
            0
        );
    }

    function test_execute_revertsMalformedTransfer() public {
        // A limited token pins the transfer selector; truncated transfer calldata (< 68 bytes) can't be decoded.
        bytes32 actorId =
            _install(_config(_limit(address(token), 500e18, WEEK), _erc20Scope(address(token), _noRecipients())));

        _mockActingActor(actorId);
        bytes memory malformed = abi.encodePacked(TRANSFER, bytes32(uint256(uint160(bob)))); // selector + 32 = 36 bytes
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.MalformedTokenCall.selector, TRANSFER));
        vm.prank(account);
        manager.execute(lastBinding, _action(address(token), 0, malformed));
    }

    function test_execute_revertsMalformedTransferFrom() public {
        // Exercises the transferFrom decode branch: a pinned transferFrom selector with calldata < 100 bytes.
        SessionPolicy.SelectorRule[] memory rules = new SessionPolicy.SelectorRule[](1);
        rules[0] = SessionPolicy.SelectorRule({selector: TRANSFER_FROM, recipients: _noRecipients()});
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = SessionPolicy.CallScope({target: address(token), selectorRules: rules});
        bytes32 actorId = _install(_config(_limit(address(token), 500e18, WEEK), scopes));

        _mockActingActor(actorId);
        bytes memory malformed = abi.encodePacked(TRANSFER_FROM, bytes32(0), bytes32(0)); // selector + 64 = 68 < 100
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.MalformedTokenCall.selector, TRANSFER_FROM));
        vm.prank(account);
        manager.execute(lastBinding, _action(address(token), 0, malformed));
    }

    // ── Views ──

    function test_views_reflectCommittedErc20Scope() public {
        address[] memory recipients = new address[](1);
        recipients[0] = bob;
        (, bytes32 commitment) = _authorizeWithCommitment(
            _config(_limit(address(token), 500e18, WEEK), _erc20Scope(address(token), recipients))
        );
        SessionPolicy.Config memory cfg = abi.decode(lastBinding.policyConfig, (SessionPolicy.Config));

        (bool allowed, bool anySelector) = policy.isTargetAllowed(cfg, address(token));
        assertTrue(allowed);
        assertFalse(anySelector);

        (bool selAllowed, bool recipientBound) = policy.getSelectorRule(cfg, address(token), TRANSFER);
        assertTrue(selAllowed);
        assertTrue(recipientBound);

        assertTrue(policy.isRecipientAllowed(cfg, address(token), TRANSFER, bob));
        assertFalse(policy.isRecipientAllowed(cfg, address(token), TRANSFER, mallory));

        (bool set, uint160 allowance, uint40 period) = policy.getTokenLimit(cfg, address(token));
        assertTrue(set);
        assertEq(allowance, 500e18);
        assertEq(period, WEEK);

        assertEq(policy.getCurrentSpend(commitment, cfg.tokenLimits[0]).spend, 0);
    }

    function test_views_reflectAnySelectorScopeAndOneTimeLimit() public {
        _authorize(_config(_limit(address(0), 1 ether, 0), _anySelectorScopes(address(target))));
        SessionPolicy.Config memory cfg = abi.decode(lastBinding.policyConfig, (SessionPolicy.Config));

        (bool allowed, bool anySelector) = policy.isTargetAllowed(cfg, address(target));
        assertTrue(allowed);
        assertTrue(anySelector);

        // Unlisted target resolves to the zero scope.
        (bool otherAllowed,) = policy.isTargetAllowed(cfg, address(token));
        assertFalse(otherAllowed);

        // A one-time (period == 0) native cap is normalized to the never-resetting ONE_TIME period.
        (bool set,, uint40 period) = policy.getTokenLimit(cfg, address(0));
        assertTrue(set);
        assertEq(period, type(uint40).max);
    }

    // ── Helpers ──

    bytes4 internal constant TRANSFER_FROM = bytes4(keccak256("transferFrom(address,address,uint256)"));

    function _anySelectorScopes(address t) internal pure returns (SessionPolicy.CallScope[] memory scopes) {
        scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = _anySelectorScope(t);
    }

    /// @dev Like {_authorize} but also returns the binding's commitment, for asserting on the commitment-keyed views.
    function _authorizeWithCommitment(bytes memory policyConfig)
        internal
        returns (bytes32 actorId, bytes32 commitment)
    {
        PolicyManager.PolicyBinding memory binding;
        (actorId, binding) = _prepareBinding(policyConfig);
        lastBinding = binding;
        commitment = manager.commitmentOf(binding);
    }

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
        manager.execute(lastBinding, _action(t, value, data));
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

    /// @dev Authorize a fresh session-key actor gated to the manager committing to `policyConfig`. Returns the
    ///      actorId. Stashes the binding for subsequent {_execute} calls.
    function _authorize(bytes memory policyConfig) internal returns (bytes32 actorId) {
        PolicyManager.PolicyBinding memory binding;
        (actorId, binding) = _prepareBinding(policyConfig);
        lastBinding = binding;
    }

    /// @dev Alias kept for readability at call sites that previously "installed" a session.
    function _install(bytes memory policyConfig) internal returns (bytes32 actorId) {
        return _authorize(policyConfig);
    }

    /// @dev Authorize a fresh session-key actor committing to `policyConfig` and return the (actorId, binding).
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

        AccountConfiguration.ActorConfig memory cfg =
            AccountConfiguration.ActorConfig({authenticator: address(k1Authenticator), scope: SCOPE_POLICY, expiry: 0});
        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
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
