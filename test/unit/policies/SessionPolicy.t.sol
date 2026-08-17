// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "../../../src/Keystore.sol";
import {ITransactionContext, TX_CONTEXT_ADDRESS} from "../../../src/interfaces/ITransactionContext.sol";
import {TRUSTED_EXECUTOR} from "../../../src/accounts/DefaultAccount.sol";

import {PolicyManager} from "../../../src/policies/PolicyManager.sol";
import {SessionPolicy} from "../../../src/policies/SessionPolicy.sol";
import {RecurringAllowance} from "../../../src/policies/RecurringAllowance.sol";

import {KeystoreTest} from "../../lib/KeystoreTest.sol";

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

/// @notice Exercises the unified {SessionPolicy}: target allowlist, per-target selector allowlists, per-asset
///         recipient allowlists, per-token recurring/one-time spend limits (as the primary spend grant), native-ETH
///         limits, and the atomic multi-dimension check on a single call.
contract SessionPolicyTest is KeystoreTest {
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

    bytes4 internal constant TRANSFER = bytes4(keccak256("transfer(address,uint256)"));
    bytes4 internal constant TRANSFER_FROM = bytes4(keccak256("transferFrom(address,address,uint256)"));
    bytes4 internal constant APPROVE = bytes4(keccak256("approve(address,uint256)"));
    bytes4 internal constant MINT = bytes4(keccak256("mint(address,uint256)"));
    bytes4 internal constant OTHER_SELECTOR = bytes4(0x12345678);
    bytes4 internal constant UNKNOWN_SELECTOR = bytes4(0xaabbccdd);
    uint40 internal constant WEEK = 7 days;

    uint256 internal saltNonce;
    PolicyManager.PolicyBinding internal lastBinding;

    function setUp() public override {
        super.setUp();
        vm.warp(1_700_000_000);

        manager = new PolicyManager(address(keystore));
        policy = new SessionPolicy(address(manager));
        token = new SessionMockERC20();
        target = new SessionMockTarget();

        account = _createAccountWithRootAndManager();
        token.mint(account, 1_000_000e18);
        vm.deal(account, 100 ether);
    }

    // ── Target gating ──

    function test_target_allowsListedTarget() public {
        bytes32 actorId = _install(_config(_noLimits(), _anySelectorScopes(address(target))));

        _execute(actorId, address(target), 0, abi.encodeCall(SessionMockTarget.setValue, (42)));
        assertEq(target.value(), 42);
    }

    function test_target_revertsUnlistedTarget() public {
        bytes32 actorId = _install(_config(_noLimits(), _anySelectorScopes(address(target))));

        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.TargetNotAllowed.selector, address(token)));
        vm.prank(account);
        manager.execute(lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 1))));
    }

    // ── Selector gating (explicit CallScope, no spend cap) ──

    function test_selector_allowsListedSelector() public {
        SessionPolicy.CallScope[] memory scopes = _scope(address(target), _sel1(SessionMockTarget.setValue.selector));
        bytes32 actorId = _install(_config(_noLimits(), scopes));

        _execute(actorId, address(target), 0, abi.encodeCall(SessionMockTarget.setValue, (7)));
        assertEq(target.value(), 7);
    }

    function test_selector_revertsUnlistedSelector() public {
        SessionPolicy.CallScope[] memory scopes = _scope(address(target), _sel1(SessionMockTarget.setValue.selector));
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

    // ── Case 1: a TokenLimit by itself grants the three tracked selectors ──

    function test_case1_tokenLimitOnly_allowsTransfer() public {
        bytes32 actorId = _install(_config(_limit(address(token), 500e18, WEEK), _noScopes()));

        _execute(actorId, address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 300e18)));
        assertEq(token.balanceOf(bob), 300e18);
    }

    function test_case1_tokenLimitOnly_allowsApprove() public {
        bytes32 actorId = _install(_config(_limit(address(token), 500e18, WEEK), _noScopes()));

        _execute(actorId, address(token), 0, abi.encodeCall(SessionMockERC20.approve, (bob, 10e18)));
        assertEq(token.allowance(account, bob), 10e18);
    }

    function test_case1_tokenLimitOnly_revertsUntrackedSelector() public {
        // A TokenLimit-only grant permits ONLY transfer/transferFrom/approve — any other selector is rejected.
        bytes32 actorId = _install(_config(_limit(address(token), 500e18, WEEK), _noScopes()));

        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.SelectorNotAllowed.selector, address(token), MINT));
        vm.prank(account);
        manager.execute(lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.mint, (bob, 1))));
    }

    function test_case1_tokenLimitOnly_revertsBareValueTransfer() public {
        // Empty calldata is a plain value transfer; a TokenLimit-only target cannot receive one (needs a CallScope).
        bytes32 actorId = _install(_config(_limit(address(token), 500e18, WEEK), _noScopes()));

        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.TargetNotAllowed.selector, address(token)));
        vm.prank(account);
        manager.execute(lastBinding, _action(address(token), 0, ""));
    }

    // ── Case 2: TokenLimit + anySelector CallScope opens all selectors (untracked ones uncapped) ──

    function test_case2_anySelectorOnLimitedToken_allowsUntrackedButStillCapsTracked() public {
        SessionPolicy.TokenLimit[] memory limits = _limit(address(token), 500e18, WEEK);
        SessionPolicy.CallScope[] memory scopes = _anySelectorScopes(address(token));
        bytes32 actorId = _install(_config(limits, scopes));

        // Untracked selector is allowed (explicit opt-in) and NOT debited.
        _execute(actorId, address(token), 0, abi.encodeCall(SessionMockERC20.mint, (bob, 1e18)));
        assertEq(token.balanceOf(bob), 1e18);

        // Tracked selector is still capped.
        _execute(actorId, address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 400e18)));
        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, 600e18, 500e18));
        vm.prank(account);
        manager.execute(
            lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 200e18)))
        );
    }

    // ── Case 3: TokenLimit + explicit selectors (caps tracked, allows listed untracked, rejects unlisted) ──

    function test_case3_explicitSelectors_capsTrackedAllowsListedUntracked() public {
        SessionPolicy.TokenLimit[] memory limits = _limit(address(token), 500e18, WEEK);
        SessionPolicy.CallScope[] memory scopes = _scope(address(token), _sel2(TRANSFER, MINT));
        bytes32 actorId = _install(_config(limits, scopes));

        // Listed untracked selector: allowed, uncapped.
        _execute(actorId, address(token), 0, abi.encodeCall(SessionMockERC20.mint, (bob, 1e18)));
        // Listed tracked selector: capped.
        _execute(actorId, address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 100e18)));

        // Unlisted selector (approve) is rejected — the explicit list replaces the Case-1 default.
        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.SelectorNotAllowed.selector, address(token), APPROVE));
        vm.prank(account);
        manager.execute(lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.approve, (bob, 1))));
    }

    // ── Recipient gating (on the TokenLimit) ──

    function test_recipient_allowsListedRecipient() public {
        bytes32 actorId = _install(_config(_limitTo(address(token), 500e18, WEEK, _addr1(bob)), _noScopes()));

        _execute(actorId, address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 100e18)));
        assertEq(token.balanceOf(bob), 100e18);
    }

    function test_recipient_revertsUnlistedRecipient() public {
        bytes32 actorId = _install(_config(_limitTo(address(token), 500e18, WEEK, _addr1(bob)), _noScopes()));

        _mockActingActor(actorId);
        vm.expectRevert(
            abi.encodeWithSelector(SessionPolicy.RecipientNotAllowed.selector, address(token), TRANSFER, mallory)
        );
        vm.prank(account);
        manager.execute(
            lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (mallory, 1)))
        );
    }

    function test_recipient_appliesToApproveSpender() public {
        // The recipient list is a merged destination set: it also gates approve's spender.
        bytes32 actorId = _install(_config(_limitTo(address(token), 500e18, WEEK, _addr1(bob)), _noScopes()));

        _execute(actorId, address(token), 0, abi.encodeCall(SessionMockERC20.approve, (bob, 1e18)));
        assertEq(token.allowance(account, bob), 1e18);

        _mockActingActor(actorId);
        vm.expectRevert(
            abi.encodeWithSelector(SessionPolicy.RecipientNotAllowed.selector, address(token), APPROVE, mallory)
        );
        vm.prank(account);
        manager.execute(lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.approve, (mallory, 1))));
    }

    // ── Recurring spend limit ──

    function test_recurringLimit_withinAllowance() public {
        bytes32 actorId = _install(_config(_limit(address(token), 500e18, WEEK), _noScopes()));

        _execute(actorId, address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 300e18)));
        assertEq(token.balanceOf(bob), 300e18);
    }

    function test_recurringLimit_revertsWhenExceeded() public {
        bytes32 actorId = _install(_config(_limit(address(token), 500e18, WEEK), _noScopes()));
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
        bytes32 actorId = _install(_config(_limit(address(token), 500e18, WEEK), _noScopes()));
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
        bytes32 actorId = _install(_config(_limit(address(token), 500e18, 0), _noScopes()));
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
        bytes32 actorId = _install(_config(_limit(address(0), 1 ether, WEEK), _anySelectorScopes(bob)));
        _mockActingActor(actorId);

        vm.prank(account);
        manager.execute(lastBinding, _action(bob, 0.6 ether, ""));
        assertEq(bob.balance, 0.6 ether);

        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, 1.2 ether, 1 ether));
        vm.prank(account);
        manager.execute(lastBinding, _action(bob, 0.6 ether, ""));
    }

    function test_nativeValue_revertsWhenNoNativeLimit() public {
        // Fail closed: a call carrying value with no address(0) TokenLimit is rejected, not forwarded unbounded.
        bytes32 actorId = _install(_config(_noLimits(), _anySelectorScopes(bob)));
        _mockActingActor(actorId);

        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.NativeValueNotAllowed.selector, 1 ether));
        vm.prank(account);
        manager.execute(lastBinding, _action(bob, 1 ether, ""));
    }

    function test_nativeValue_erc20LimitDoesNotAuthorizeEth() public {
        // A token cap (e.g. "USDC 5/month") must not implicitly permit ETH: value to any target still fails closed.
        bytes32 actorId = _install(_config(_limit(address(token), 5e6, WEEK), _noScopes()));
        _mockActingActor(actorId);

        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.NativeValueNotAllowed.selector, 1 ether));
        vm.prank(account);
        manager.execute(
            lastBinding, _action(address(token), 1 ether, abi.encodeCall(SessionMockERC20.transfer, (bob, 0)))
        );
    }

    function test_nativeValue_unlimitedIdiomPermitsLargeTransfer() public {
        // The documented "unlimited ETH" idiom: a uint160.max cap is never reached in practice.
        bytes32 actorId = _install(_config(_limit(address(0), type(uint160).max, WEEK), _anySelectorScopes(bob)));
        _mockActingActor(actorId);

        vm.deal(account, 1_000_000 ether);
        vm.prank(account);
        manager.execute(lastBinding, _action(bob, 1_000_000 ether, ""));
        assertEq(bob.balance, 1_000_000 ether);
    }

    function test_nativeRecipient_gatesDestination() public {
        // A native TokenLimit with recipients gates which target may receive ETH.
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](2);
        scopes[0] = _anySelectorScope(bob);
        scopes[1] = _anySelectorScope(mallory);
        bytes32 actorId = _install(_config(_limitTo(address(0), 1 ether, WEEK, _addr1(bob)), scopes));
        _mockActingActor(actorId);

        // Allowed destination.
        vm.prank(account);
        manager.execute(lastBinding, _action(bob, 0.3 ether, ""));
        assertEq(bob.balance, 0.3 ether);

        // Disallowed destination: mallory is a valid target but not an allowed ETH recipient.
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.RecipientNotAllowed.selector, mallory, bytes4(0), mallory));
        vm.prank(account);
        manager.execute(lastBinding, _action(mallory, 0.1 ether, ""));
    }

    // ── Atomic multi-dimension enforcement on a single call ──

    function test_multiDimension_passesAllAtOnce() public {
        bytes32 actorId = _install(_config(_limitTo(address(token), 500e18, WEEK, _addr1(bob)), _noScopes()));

        // target + selector + recipient + within-limit all satisfied in one call.
        _execute(actorId, address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 250e18)));
        assertEq(token.balanceOf(bob), 250e18);
    }

    function test_multiDimension_recipientFailsEvenWithinLimit() public {
        bytes32 actorId = _install(_config(_limitTo(address(token), 500e18, WEEK, _addr1(bob)), _noScopes()));

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
    // most $5 of USDC per month (a TokenLimit-only grant); and (3) may call the MyApp app contract as much as it
    // wants, but only through two chosen selectors.

    function test_workedExample_fullTokenAccess_monthlyUsdc_appSelectors() public {
        // A second ERC-20 plays the role of USDC (6 decimals); `token` (minted in setUp) is the MyApp token.
        SessionMockERC20 usdc = new SessionMockERC20();
        usdc.mint(account, 1_000e6);
        uint40 monthPeriod = 30 days;
        uint256 fiveUsdc = 5e6; // $5 at 6 decimals

        // Spend limits: only USDC ($5/month), a Case-1 grant (no CallScope needed for the three spend selectors).
        SessionPolicy.TokenLimit[] memory limits = _limit(address(usdc), fiveUsdc, monthPeriod);

        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](2);
        // (a) MyApp token: full access — any selector, and no spend cap (no TokenLimit above).
        scopes[0] = _anySelectorScope(address(token));
        // (b) MyApp app contract: two chosen selectors, unlimited calls.
        scopes[1] =
            _scopeOne(address(target), _sel2(SessionMockTarget.setValue.selector, SessionMockTarget.other.selector));

        bytes32 actorId = _install(_config(limits, scopes));

        // Uncapped MyApp token transfer.
        _execute(actorId, address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 750_000e18)));
        assertEq(token.balanceOf(bob), 750_000e18);

        // USDC within the monthly cap (Case 1: transfer permitted by the limit alone).
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

    function test_execute_revertsZeroLimit() public {
        bytes32 actorId = _authorize(_config(_limit(address(token), 0, WEEK), _noScopes()));
        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.ZeroLimit.selector, address(token)));
        vm.prank(account);
        manager.execute(lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 1))));
    }

    function test_execute_revertsLimitTooLarge() public {
        uint256 tooLarge = uint256(type(uint160).max) + 1;
        bytes32 actorId = _authorize(_config(_limit(address(token), tooLarge, WEEK), _noScopes()));
        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.LimitTooLarge.selector, address(token), tooLarge));
        vm.prank(account);
        manager.execute(lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 1))));
    }

    function test_execute_revertsSelfTarget() public {
        bytes32 actorId = _authorize(_config(_noLimits(), _anySelectorScopes(account)));
        _mockActingActor(actorId);
        vm.expectRevert(SessionPolicy.SelfTargetNotAllowed.selector);
        vm.prank(account);
        manager.execute(lastBinding, _action(account, 0, ""));
    }

    function test_execute_revertsDuplicateTokenLimit() public {
        SessionPolicy.TokenLimit[] memory limits = new SessionPolicy.TokenLimit[](2);
        limits[0] = _tl(address(token), 100e18, WEEK, _noRecipients());
        limits[1] = _tl(address(token), 200e18, WEEK, _noRecipients());
        bytes32 actorId = _authorize(_config(limits, _noScopes()));
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

    function test_execute_revertsDuplicateSelector() public {
        SessionPolicy.CallScope[] memory scopes = _scope(address(token), _sel2(TRANSFER, TRANSFER));
        bytes32 actorId = _authorize(_config(_noLimits(), scopes));
        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.DuplicateSelector.selector, address(token), TRANSFER));
        vm.prank(account);
        manager.execute(lastBinding, _action(address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 1))));
    }

    // ── Calldata config preimage ──

    function test_execute_revertsOnPolicyConfigMismatch() public {
        // Execute must re-supply the exact committed binding; the manager recomputes the commitment.
        bytes32 actorId = _authorize(_config(_noLimits(), _anySelectorScopes(address(target))));
        bytes32 commitment = keystore.getPolicyCommitment(account, actorId);

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
        bytes32 actorId = _install(_config(_noLimits(), _anySelectorScopes(address(target))));

        _mockActingActor(actorId);
        vm.expectRevert(SessionPolicy.MissingSelector.selector);
        vm.prank(account);
        manager.execute(lastBinding, _action(address(target), 0, hex"010203"));
    }

    function test_execute_acceptsTransferDespiteDirtySelectorWord() public {
        // ABI-encoded `transfer` packs the selector into the high 4 bytes of the first word and the address into
        // the remainder — so a raw mload into bytes4 leaves dirty low bytes. The mask must still match TRANSFER.
        bytes32 actorId = _install(_config(_limit(address(token), 500e18, WEEK), _noScopes()));
        _execute(actorId, address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 1e18)));
        assertEq(token.balanceOf(bob), 1e18);
    }

    function test_execute_revertsTransferFromNotSelf() public {
        bytes32 actorId = _install(_config(_limit(address(token), 500e18, WEEK), _noScopes()));

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

    function test_execute_allowsApproveDecodesSpender() public {
        // A Case-1 limited token exercises the APPROVE leg of the ERC-20 decoder (`selector == APPROVE`).
        bytes32 actorId = _install(_config(_limit(address(token), 500e18, WEEK), _noScopes()));

        _execute(actorId, address(token), 0, abi.encodeCall(SessionMockERC20.approve, (bob, 1e18)));
        assertEq(token.allowance(account, bob), 1e18);
    }

    function test_execute_allowsSelfTransferFromDecodesAmount() public {
        // A self-transferFrom (from == account) with a token limit passes the TransferFromNotSelf gate and reaches
        // the ERC-20 amount decode — the else (transferFrom) leg of _decodeErc20 — then consumes the decoded amount.
        (bytes32 actorId, bytes32 commitment) =
            _authorizeWithCommitment(_config(_limit(address(token), 500e18, WEEK), _noScopes()));

        // Fund the account and let it pull from itself so the underlying transferFrom succeeds.
        token.mint(account, 100e18);
        vm.prank(account);
        token.approve(account, 100e18);

        _execute(actorId, address(token), 0, abi.encodeCall(SessionMockERC20.transferFrom, (account, bob, 10e18)));

        // The decoded amount was consumed against the token cap, proving the transferFrom decode leg ran.
        assertEq(policy.getCurrentSpend(commitment, _tl(address(token), 500e18, WEEK, _noRecipients())).spend, 10e18);
        assertEq(token.balanceOf(bob), 10e18);
    }

    /// @notice Defensive guard: _findTokenLimit re-checks LimitTooLarge before the uint160 cast even though
    ///         _validateConfig already rejects it at enforce entry. Reached only via a harness that bypasses
    ///         validation, since the enforce path can never present an oversized limit here.
    function test_findTokenLimit_revert_limitTooLargeDefensive() public {
        SessionPolicyHarness harness = new SessionPolicyHarness(address(manager));
        uint256 tooLarge = uint256(type(uint160).max) + 1;

        SessionPolicy.TokenLimit[] memory limits = _limit(address(token), tooLarge, WEEK);
        SessionPolicy.Config memory cfg =
            SessionPolicy.Config({tokenLimits: limits, callScopes: new SessionPolicy.CallScope[](0)});

        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.LimitTooLarge.selector, address(token), tooLarge));
        harness.exposedFindTokenLimit(cfg, address(token));
    }

    function test_execute_allowsEmptyCalldata() public {
        // 0 bytes of calldata is a plain value call against a CallScope target: it skips selector gating entirely.
        bytes32 actorId = _install(_config(_noLimits(), _anySelectorScopes(bob)));

        _execute(actorId, bob, 0, "");
    }

    // ── ERC-20 spend accounting edge cases ──

    function test_execute_zeroAmountTransferSkipsSpend() public {
        // A zero-value transfer on a limited token must not touch spend accounting (the library rejects zero spends).
        (bytes32 actorId, bytes32 commitment) =
            _authorizeWithCommitment(_config(_limit(address(token), 500e18, WEEK), _noScopes()));

        _execute(actorId, address(token), 0, abi.encodeCall(SessionMockERC20.transfer, (bob, 0)));

        assertEq(policy.getCurrentSpend(commitment, _tl(address(token), 500e18, WEEK, _noRecipients())).spend, 0);
    }

    function test_execute_revertsMalformedTransfer() public {
        // A Case-1 limited token; truncated transfer calldata (< 68 bytes) can't be decoded.
        bytes32 actorId = _install(_config(_limit(address(token), 500e18, WEEK), _noScopes()));

        _mockActingActor(actorId);
        bytes memory malformed = abi.encodePacked(TRANSFER, bytes32(uint256(uint160(bob)))); // selector + 32 = 36 bytes
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.MalformedTokenCall.selector, TRANSFER));
        vm.prank(account);
        manager.execute(lastBinding, _action(address(token), 0, malformed));
    }

    function test_execute_revertsMalformedTransferFrom() public {
        // Exercises the transferFrom decode branch: a Case-1 limited token with calldata < 100 bytes.
        bytes32 actorId = _install(_config(_limit(address(token), 500e18, WEEK), _noScopes()));

        _mockActingActor(actorId);
        bytes memory malformed = abi.encodePacked(TRANSFER_FROM, bytes32(0), bytes32(0)); // selector + 64 = 68 < 100
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.MalformedTokenCall.selector, TRANSFER_FROM));
        vm.prank(account);
        manager.execute(lastBinding, _action(address(token), 0, malformed));
    }

    // ── Views ──

    function test_views_reflectCommittedLimitedToken() public {
        (, bytes32 commitment) =
            _authorizeWithCommitment(_config(_limitTo(address(token), 500e18, WEEK, _addr1(bob)), _noScopes()));
        SessionPolicy.Config memory cfg = abi.decode(lastBinding.policyConfig, (SessionPolicy.Config));

        // A TokenLimit-only token is callable (Case 1), reporting anySelector == false.
        (bool allowed, bool anySelector) = policy.isTargetAllowed(cfg, address(token));
        assertTrue(allowed);
        assertFalse(anySelector);

        (bool selAllowed, bool recipientBound) = policy.getSelectorRule(cfg, address(token), TRANSFER);
        assertTrue(selAllowed);
        assertTrue(recipientBound);

        // A non-tracked selector is not allowed on a Case-1 token.
        (bool mintAllowed,) = policy.getSelectorRule(cfg, address(token), MINT);
        assertFalse(mintAllowed);

        assertTrue(policy.isRecipientAllowed(cfg, address(token), TRANSFER, bob));
        assertFalse(policy.isRecipientAllowed(cfg, address(token), TRANSFER, mallory));

        (bool set, uint160 allowance, uint40 period) = policy.getTokenLimit(cfg, address(token));
        assertTrue(set);
        assertEq(allowance, 500e18);
        assertEq(period, WEEK);

        assertEq(policy.getTokenRecipients(cfg, address(token)).length, 1);
        assertEq(policy.getTokenRecipients(cfg, address(token))[0], bob);

        assertEq(policy.getCurrentSpend(commitment, cfg.tokenLimits[0]).spend, 0);
    }

    function test_views_reflectAnySelectorScopeAndOneTimeLimit() public {
        _authorize(_config(_limit(address(0), 1 ether, 0), _anySelectorScopes(address(target))));
        SessionPolicy.Config memory cfg = abi.decode(lastBinding.policyConfig, (SessionPolicy.Config));

        (bool allowed, bool anySelector) = policy.isTargetAllowed(cfg, address(target));
        assertTrue(allowed);
        assertTrue(anySelector);

        // Unlisted target (and not a limited token) resolves to not-allowed.
        (bool otherAllowed,) = policy.isTargetAllowed(cfg, address(token));
        assertFalse(otherAllowed);

        // A one-time (period == 0) native cap is normalized to the never-resetting ONE_TIME period.
        (bool set,, uint40 period) = policy.getTokenLimit(cfg, address(0));
        assertTrue(set);
        assertEq(period, type(uint40).max);
    }

    /// @notice Exercises the mismatch/empty branches of the views: a non-matching target is skipped, an any-selector
    ///         scope resolves without a recipient binding, an unknown selector on an explicit scope resolves to
    ///         (false,false), and recipient gating comes from the TokenLimit.
    function test_views_selectorAndRecipientEdges() public view {
        SessionPolicy.TokenLimit[] memory limits = _limitTo(address(token), 500e18, WEEK, _addr1(bob));

        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](2);
        scopes[0] = _scopeOne(address(token), _sel1(TRANSFER)); // Case 3: explicit selectors on the limited token
        scopes[1] = _anySelectorScope(address(target)); // any selector (empty list), no limit

        SessionPolicy.Config memory cfg = SessionPolicy.Config({tokenLimits: limits, callScopes: scopes});

        // getSelectorRule: any-selector scope allows any selector, with no recipient binding (no limit on target).
        (bool allowed, bool recipientBound) = policy.getSelectorRule(cfg, address(target), TRANSFER);
        assertTrue(allowed);
        assertFalse(recipientBound);

        // getSelectorRule: explicit scope on token, unknown selector → (false, false).
        (allowed, recipientBound) = policy.getSelectorRule(cfg, address(token), UNKNOWN_SELECTOR);
        assertFalse(allowed);
        assertFalse(recipientBound);

        // getSelectorRule: token/TRANSFER is listed and the limit pins recipients → recipientBound true.
        (allowed, recipientBound) = policy.getSelectorRule(cfg, address(token), TRANSFER);
        assertTrue(allowed);
        assertTrue(recipientBound);

        // isRecipientAllowed: untracked selector is unrestricted.
        assertTrue(policy.isRecipientAllowed(cfg, address(token), OTHER_SELECTOR, mallory));

        // isRecipientAllowed: no limit on target → unrestricted.
        assertTrue(policy.isRecipientAllowed(cfg, address(target), TRANSFER, mallory));

        // isRecipientAllowed: token/TRANSFER is bound to bob only.
        assertTrue(policy.isRecipientAllowed(cfg, address(token), TRANSFER, bob));
        assertFalse(policy.isRecipientAllowed(cfg, address(token), TRANSFER, mallory));
    }

    /// @notice getCurrentSpend short-circuits to an empty usage when the queried limit is zero.
    function test_getCurrentSpend_zeroLimitReturnsEmpty() public view {
        RecurringAllowance.PeriodUsage memory u =
            policy.getCurrentSpend(bytes32(0), _tl(address(token), 0, WEEK, _noRecipients()));
        assertEq(u.start, 0);
        assertEq(u.end, 0);
        assertEq(u.spend, 0);
    }

    /// @notice getCurrentSpend rejects a limit that does not fit in uint160 (matching the config-time invariant).
    function test_getCurrentSpend_revertsLimitTooLarge() public {
        uint256 tooLarge = uint256(type(uint160).max) + 1;
        vm.expectRevert(abi.encodeWithSelector(SessionPolicy.LimitTooLarge.selector, address(token), tooLarge));
        policy.getCurrentSpend(bytes32(0), _tl(address(token), tooLarge, WEEK, _noRecipients()));
    }

    // ── Helpers ──

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

    function _noScopes() internal pure returns (SessionPolicy.CallScope[] memory) {
        return new SessionPolicy.CallScope[](0);
    }

    function _noRecipients() internal pure returns (address[] memory) {
        return new address[](0);
    }

    function _addr1(address a) internal pure returns (address[] memory arr) {
        arr = new address[](1);
        arr[0] = a;
    }

    function _tl(address tkn, uint256 lim, uint40 period, address[] memory recipients)
        internal
        pure
        returns (SessionPolicy.TokenLimit memory)
    {
        return SessionPolicy.TokenLimit({token: tkn, limit: lim, period: period, recipients: recipients});
    }

    function _limit(address tkn, uint256 lim, uint40 period)
        internal
        pure
        returns (SessionPolicy.TokenLimit[] memory limits)
    {
        limits = new SessionPolicy.TokenLimit[](1);
        limits[0] = _tl(tkn, lim, period, _noRecipients());
    }

    function _limitTo(address tkn, uint256 lim, uint40 period, address[] memory recipients)
        internal
        pure
        returns (SessionPolicy.TokenLimit[] memory limits)
    {
        limits = new SessionPolicy.TokenLimit[](1);
        limits[0] = _tl(tkn, lim, period, recipients);
    }

    function _sel1(bytes4 a) internal pure returns (bytes4[] memory s) {
        s = new bytes4[](1);
        s[0] = a;
    }

    function _sel2(bytes4 a, bytes4 b) internal pure returns (bytes4[] memory s) {
        s = new bytes4[](2);
        s[0] = a;
        s[1] = b;
    }

    function _anySelectorScope(address t) internal pure returns (SessionPolicy.CallScope memory) {
        return SessionPolicy.CallScope({target: t, selectors: new bytes4[](0)});
    }

    function _scopeOne(address t, bytes4[] memory selectors) internal pure returns (SessionPolicy.CallScope memory) {
        return SessionPolicy.CallScope({target: t, selectors: selectors});
    }

    function _scope(address t, bytes4[] memory selectors)
        internal
        pure
        returns (SessionPolicy.CallScope[] memory scopes)
    {
        scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = _scopeOne(t, selectors);
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
            authenticator: TRUSTED_EXECUTOR,
            scope: 0,
            policyData: ""
        });

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](2);
        (actors[0], actors[1]) = root.actorId < mgr.actorId ? (root, mgr) : (mgr, root);

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        return keystore.createAccount(bytes32(0), bytecode, actors);
    }

    /// @dev Authorize a fresh session-key actor gated to the manager committing to `policyConfig`. Returns the
    ///      actorId. Stashes the binding for subsequent {_execute} calls.
    function _authorize(bytes memory policyConfig) internal returns (bytes32 actorId) {
        PolicyManager.PolicyBinding memory binding;
        (actorId, binding) = _prepareBinding(policyConfig);
        lastBinding = binding;
    }

    /// @dev Alias for `_authorize`, named for readability at call sites that read as "installing" a session.
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

        // Authorize the fresh session-key actor gated to the manager, granted UNBOUNDED (the new "no expiry") on a
        // sequenced local batch, signed by the root owner.
        _applyLocal(
            ROOT_PK,
            account,
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
}

/// @dev Exposes {SessionPolicy._findTokenLimit} so the defensive LimitTooLarge guard — unreachable through the
///      validated {_enforce} path — can be exercised directly with an oversized limit.
contract SessionPolicyHarness is SessionPolicy {
    constructor(address policyManager) SessionPolicy(policyManager) {}

    function exposedFindTokenLimit(SessionPolicy.Config calldata config, address token)
        external
        pure
        returns (bool set, uint160 allowance, uint40 period)
    {
        (bool s, SessionPolicy.TokenLimit memory tl) = _findTokenLimit(config, token);
        return (s, uint160(tl.limit), tl.period == 0 ? ONE_TIME_PERIOD : tl.period);
    }
}
