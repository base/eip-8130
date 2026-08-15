// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";

import {Call, DefaultAccount} from "../accounts/DefaultAccount.sol";
import {Policy} from "./Policy.sol";
import {RecurringAllowance} from "./RecurringAllowance.sol";

/// @title SessionPolicy
///
/// @notice Unified EIP-8130 "session key" policy combining, in a single committed binding and a single per-call
///         check: a call-target allowlist, per-target function-selector rules, optional per-selector recipient
///         allowlists, and per-token (and native-ETH) recurring/one-time spend limits.
///
/// @dev Config is never stored: {onExecute} receives the config preimage via calldata, authenticated by the
///      manager's binding-commitment check, and {_validateConfig} re-checks its shape at execute. The only storage
///      is {_usage} (spend accounting).
///
///      Decoding limitation: only the standard ERC-20 selectors (`transfer`, `transferFrom`, `approve`) are decoded
///      for recipient allowlists and spend accounting. Any other selector on a limited token is gated by the
///      allowlist but NOT debited from the cap, so do not allowlist value-moving non-ERC-20 methods on a token you
///      intend to bound; `anySelector` on a limited token is rejected at execute.
///
///      Native ETH fails closed: a call carrying `value` reverts unless the config pins a native {TokenLimit}
///      (`token == address(0)`). `approve` is debited at grant time, so a standing allowance pulled later can still
///      exceed a single period's cap. Empty calldata is allowed; 1-3 bytes revert ({MissingSelector}); 4+ bytes are
///      treated as a selector.
contract SessionPolicy is Policy {
    using RecurringAllowance for RecurringAllowance.State;

    // ── Committed configuration (what the account signs; re-supplied at every execute) ──

    /// @notice Per-token (or native-ETH) spend cap.
    struct TokenLimit {
        /// @dev ERC-20 token address, or address(0) for native ETH (gated on each call's `value`).
        address token;
        /// @dev Maximum spend per period (one-time: total cap). Must fit uint160; 0 is rejected ({ZeroLimit}). To
        ///      express an effectively unlimited budget, set `limit = type(uint160).max`.
        uint256 limit;
        /// @dev Recurring period in seconds. 0 = one-time (a single cumulative cap that never resets).
        uint40 period;
    }

    /// @notice A function selector and an optional recipient allowlist.
    struct SelectorRule {
        /// @dev 4-byte function selector allowed on the parent {CallScope} target.
        bytes4 selector;
        /// @dev Allowed recipients (empty = any recipient). Only valid for known ERC-20 selectors.
        address[] recipients;
    }

    /// @notice A target contract and its allowed selector rules.
    struct CallScope {
        /// @dev Target contract this binding may call.
        address target;
        /// @dev Allowed selectors on `target` (empty = any selector allowed, no recipient gating).
        SelectorRule[] selectorRules;
    }

    /// @notice The full committed configuration for a binding.
    struct Config {
        /// @dev Per-token (and native-ETH) spend caps.
        TokenLimit[] tokenLimits;
        /// @dev Allowed call targets and their selector rules.
        CallScope[] callScopes;
    }

    /// @notice Per-use action: a single call the session key wants the account to make.
    struct Action {
        /// @dev Target contract the account will call.
        address target;
        /// @dev Wei forwarded with the call.
        uint256 value;
        /// @dev Calldata for the call (empty = plain value transfer).
        bytes data;
    }

    // ── Storage: mutable spend usage only ──

    /// @dev Recurring-allowance usage, keyed by keccak256(commitment, token).
    RecurringAllowance.State internal _usage;

    // ── ERC-20 selectors this policy can decode for recipient + amount semantics ──

    bytes4 internal constant TRANSFER = IERC20.transfer.selector; // transfer(address,uint256)
    bytes4 internal constant TRANSFER_FROM = IERC20.transferFrom.selector; // transferFrom(address,address,uint256)
    bytes4 internal constant APPROVE = IERC20.approve.selector; // approve(address,uint256)

    /// @dev One-time limits are modeled as a never-resetting window: period is type(uint40).max so the cumulative
    ///      spend never refreshes within representable time.
    uint40 internal constant ONE_TIME_PERIOD = type(uint40).max;

    /// @notice The action's `target` is not in the committed call-target allowlist.
    error TargetNotAllowed(address target);

    /// @notice `selector` is not permitted on `target` (the target pins an explicit selector allowlist that omits it).
    error SelectorNotAllowed(address target, bytes4 selector);

    /// @notice `recipient` (decoded from the ERC-20 call) is not in the selector's committed recipient allowlist.
    error RecipientNotAllowed(address target, bytes4 selector, address recipient);

    /// @notice The action carried 1–3 bytes of calldata: too short to hold a 4-byte selector, so it is rejected rather
    ///         than guessed.
    error MissingSelector();

    /// @notice A configured spend `limit` exceeds uint160 and cannot be stored in the normalized allowance field.
    error LimitTooLarge(address token, uint256 limit);

    /// @notice A configured spend limit was zero, which would be a no-op cap; reject to fail closed.
    error ZeroLimit(address token);

    /// @notice The action carried native `value` but the config pins no native-ETH limit (`token == address(0)`).
    error NativeValueNotAllowed(uint256 value);

    /// @notice A recipient allowlist was attached to a selector whose recipient argument this policy cannot decode
    ///         (only the standard ERC-20 selectors are supported).
    error RecipientRuleUnsupportedSelector(bytes4 selector);

    /// @notice A supported ERC-20 call's calldata was too short to decode its (recipient, amount) arguments.
    error MalformedTokenCall(bytes4 selector);

    /// @notice A limited token was configured with `anySelector`, which would let non-ERC-20 methods move value
    ///         without debiting the spend cap.
    error AnySelectorOnLimitedToken(address token);

    /// @notice A call scope targeted the account itself, which would let a session key re-enter `executeBatch` and
    ///         bypass every policy check.
    error SelfTargetNotAllowed();

    /// @notice A `transferFrom` moved funds from an address other than the account. A session key may only spend the
    ///         account's own resources, not third-party allowances the account happens to hold.
    error TransferFromNotSelf(address from);

    /// @notice Duplicate `TokenLimit.token` in the committed config (would silently widen / ambiguate grants).
    error DuplicateTokenLimit(address token);

    /// @notice Duplicate `CallScope.target` in the committed config.
    error DuplicateCallScope(address target);

    /// @notice Duplicate `SelectorRule.selector` within a call scope.
    error DuplicateSelectorRule(address target, bytes4 selector);

    constructor(address policyManager) Policy(policyManager) {}

    // ── View functions ──

    /// @notice Returns whether `target` is allowed by `config`, and whether any selector is permitted on it.
    ///
    /// @param config Committed policy configuration.
    /// @param target Call target to check.
    ///
    /// @return allowed     True if `target` is in the call-target allowlist.
    /// @return anySelector True if the target pins no selector allowlist (any selector permitted).
    function isTargetAllowed(Config calldata config, address target)
        external
        pure
        returns (bool allowed, bool anySelector)
    {
        for (uint256 i; i < config.callScopes.length; i++) {
            if (config.callScopes[i].target == target) {
                return (true, config.callScopes[i].selectorRules.length == 0);
            }
        }
        return (false, false);
    }

    /// @notice Returns whether `selector` is allowed on `target` by `config`, and whether a recipient allowlist
    ///         applies.
    ///
    /// @param config   Committed policy configuration.
    /// @param target   Call target the selector is checked against.
    /// @param selector Function selector to check.
    ///
    /// @return allowed        True if `selector` is permitted on `target`.
    /// @return recipientBound True if a recipient allowlist applies to the selector.
    function getSelectorRule(Config calldata config, address target, bytes4 selector)
        external
        pure
        returns (bool allowed, bool recipientBound)
    {
        for (uint256 i; i < config.callScopes.length; i++) {
            CallScope calldata scope = config.callScopes[i];
            if (scope.target != target) continue;
            if (scope.selectorRules.length == 0) return (true, false);
            for (uint256 j; j < scope.selectorRules.length; j++) {
                if (scope.selectorRules[j].selector == selector) {
                    return (true, scope.selectorRules[j].recipients.length > 0);
                }
            }
            return (false, false);
        }
        return (false, false);
    }

    /// @notice Returns whether `recipient` is in the recipient allowlist for `(target, selector)` in `config`.
    ///
    /// @param config    Committed policy configuration.
    /// @param target    Call target the selector belongs to.
    /// @param selector  Function selector the recipient allowlist is attached to.
    /// @param recipient Recipient address to check.
    ///
    /// @return True if `recipient` is allowed (or the selector has no recipient allowlist).
    function isRecipientAllowed(Config calldata config, address target, bytes4 selector, address recipient)
        external
        pure
        returns (bool)
    {
        for (uint256 i; i < config.callScopes.length; i++) {
            CallScope calldata scope = config.callScopes[i];
            if (scope.target != target) continue;
            for (uint256 j; j < scope.selectorRules.length; j++) {
                SelectorRule calldata rule = scope.selectorRules[j];
                if (rule.selector != selector) continue;
                if (rule.recipients.length == 0) return true;
                for (uint256 k; k < rule.recipients.length; k++) {
                    if (rule.recipients[k] == recipient) return true;
                }
                return false;
            }
        }
        return false;
    }

    /// @notice Returns the spend cap for `token` from `config` (normalized period for one-time limits).
    ///
    /// @param config Committed policy configuration.
    /// @param token  Token address to look up (address(0) for native ETH).
    ///
    /// @return set       True if `token` has a configured limit.
    /// @return allowance Spend cap normalized to uint160.
    /// @return period    Period in seconds ({ONE_TIME_PERIOD} for one-time limits).
    function getTokenLimit(Config calldata config, address token)
        external
        pure
        returns (bool set, uint160 allowance, uint40 period)
    {
        for (uint256 i; i < config.tokenLimits.length; i++) {
            TokenLimit calldata tl = config.tokenLimits[i];
            if (tl.token == token) {
                return (true, uint160(tl.limit), tl.period == 0 ? ONE_TIME_PERIOD : tl.period);
            }
        }
        return (false, 0, 0);
    }

    /// @notice Returns the current-period spend usage for an explicit token limit under a binding.
    ///
    /// @dev Reverts with LimitTooLarge when `limit.limit` exceeds uint160.
    /// @dev `limit` is unauthenticated calldata; results are only meaningful when it is the committed {TokenLimit}
    ///      from the binding's config. A zero `limit.period` is normalized to {ONE_TIME_PERIOD}.
    ///
    /// @param commitment Binding commitment the usage is keyed under.
    /// @param limit      Token limit to report usage for.
    ///
    /// @return Current-period usage snapshot (zeroed when `limit.limit` is zero).
    function getCurrentSpend(bytes32 commitment, TokenLimit calldata limit)
        external
        view
        returns (RecurringAllowance.PeriodUsage memory)
    {
        if (limit.limit == 0) {
            return RecurringAllowance.PeriodUsage({start: 0, end: 0, spend: 0});
        }
        if (limit.limit > type(uint160).max) revert LimitTooLarge(limit.token, limit.limit);
        uint40 period = limit.period == 0 ? ONE_TIME_PERIOD : limit.period;
        return _usage.getCurrentPeriod(
            _spendKey(commitment, limit.token),
            RecurringAllowance.Limit({allowance: uint160(limit.limit), period: period, start: 0, end: type(uint40).max})
        );
    }

    // ── Hooks ──

    /// @dev Policy execute hook: validates config, gates the decoded {Action} by linear scan, and returns the
    ///      account call plan (empty postCallData). The manager has already authenticated `policyConfig`.
    ///
    /// @dev Reverts via {_validateConfig} when the committed config is malformed.
    /// @dev Reverts with TargetNotAllowed when `action.target` is not in the call-target allowlist.
    /// @dev Reverts with SelectorNotAllowed when the call's selector is not permitted on the target.
    /// @dev Reverts with MalformedTokenCall when an ERC-20 call's calldata is too short to decode.
    /// @dev Reverts with RecipientNotAllowed when the decoded ERC-20 recipient is not in the selector's allowlist.
    /// @dev Reverts with TransferFromNotSelf when a `transferFrom` moves funds from an address other than `account`.
    /// @dev Reverts with ExceededAllowance when a token or native-ETH spend exceeds its remaining cap.
    /// @dev Reverts with MissingSelector when the action carries 1-3 bytes of calldata.
    /// @dev Reverts with NativeValueNotAllowed when the action carries `value` but no native-ETH limit is configured.
    ///
    /// @param commitment    Binding commitment authorizing this execution.
    /// @param account       Account the plan will execute against.
    /// @param policyConfig  ABI-encoded {Config} committed by the account.
    /// @param executionData ABI-encoded {Action} for this call.
    ///
    /// @return accountCallData ABI-encoded {DefaultAccount.executeBatch} plan for the single action.
    /// @return postCallData    Always empty (no post-call hook).
    function _onExecute(
        bytes32 commitment,
        address account,
        bytes calldata policyConfig,
        bytes calldata executionData,
        address
    ) internal override returns (bytes memory accountCallData, bytes memory postCallData) {
        Config memory config = abi.decode(policyConfig, (Config));
        _validateConfig(account, config);
        Action memory action = abi.decode(executionData, (Action));

        // 1. Target allowlist + resolve scope.
        (bool targetAllowed, bool anySelector, CallScope memory scope) = _findScope(config, action.target);
        if (!targetAllowed) revert TargetNotAllowed(action.target);

        // 2. Selector + recipient gating (for calls carrying a selector).
        if (action.data.length >= 4) {
            bytes4 selector = _selectorOf(action.data);

            if (!anySelector) {
                (bool selAllowed, bool recipientBound, address[] memory recipients) = _findSelectorRule(scope, selector);
                if (!selAllowed) revert SelectorNotAllowed(action.target, selector);
                if (recipientBound) {
                    (address recipient,) = _decodeErc20(selector, action.data);
                    if (!_recipientIn(recipients, recipient)) {
                        revert RecipientNotAllowed(action.target, selector, recipient);
                    }
                }
            }

            // transferFrom may only move the account's own funds (from == account), never a third-party allowance.
            if (selector == TRANSFER_FROM) {
                address from = _decodeTransferFromSender(action.data);
                if (from != account) revert TransferFromNotSelf(from);
            }

            // ERC-20 spend limit: debit the token's cap for decodable selectors (approve debits at grant time).
            if (_isErc20Selector(selector)) {
                (bool set, uint160 allowance, uint40 period) = _findTokenLimit(config, action.target);
                if (set) {
                    (, uint256 amount) = _decodeErc20(selector, action.data);
                    _consume(commitment, action.target, allowance, period, amount);
                }
            }
        } else if (action.data.length != 0) {
            // 1–3 bytes of data carry no usable selector; reject rather than guess.
            revert MissingSelector();
        }

        // Native-ETH spend limit: debit the call value; fail closed when no native limit is configured.
        if (action.value > 0) {
            (bool set, uint160 allowance, uint40 period) = _findTokenLimit(config, address(0));
            if (!set) revert NativeValueNotAllowed(action.value);
            _consume(commitment, address(0), allowance, period, action.value);
        }

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: action.target, value: action.value, data: action.data});
        return (abi.encodeCall(DefaultAccount.executeBatch, (calls)), "");
    }

    // ── Internal helpers ──

    /// @dev Validates the committed {Config} shape and rejects duplicates.
    ///
    /// @dev Reverts with ZeroLimit when a token limit is zero.
    /// @dev Reverts with LimitTooLarge when a token limit exceeds uint160.
    /// @dev Reverts with DuplicateTokenLimit when a token appears twice in `tokenLimits`.
    /// @dev Reverts with DuplicateCallScope when a target appears twice in `callScopes`.
    /// @dev Reverts with SelfTargetNotAllowed when a call scope targets `account`.
    /// @dev Reverts with AnySelectorOnLimitedToken when a limited token pins no selector allowlist.
    /// @dev Reverts with DuplicateSelectorRule when a selector appears twice within a call scope.
    /// @dev Reverts with RecipientRuleUnsupportedSelector when a recipient allowlist is attached to a non-ERC-20 selector.
    ///
    /// @param account Account the config is validated against (used for the self-target check).
    /// @param config  Committed policy configuration to validate.
    function _validateConfig(address account, Config memory config) internal pure {
        for (uint256 i; i < config.tokenLimits.length; i++) {
            TokenLimit memory tl = config.tokenLimits[i];
            if (tl.limit == 0) revert ZeroLimit(tl.token);
            if (tl.limit > type(uint160).max) revert LimitTooLarge(tl.token, tl.limit);
            for (uint256 d; d < i; d++) {
                if (config.tokenLimits[d].token == tl.token) revert DuplicateTokenLimit(tl.token);
            }
        }

        for (uint256 i; i < config.callScopes.length; i++) {
            CallScope memory scope = config.callScopes[i];
            for (uint256 d; d < i; d++) {
                if (config.callScopes[d].target == scope.target) revert DuplicateCallScope(scope.target);
            }
            // The account can always call its own executeBatch; allowing it enables policy-bypassing re-entrancy.
            if (scope.target == account) revert SelfTargetNotAllowed();
            bool anySelector = scope.selectorRules.length == 0;
            // A TokenLimit only tracks ERC-20 transfer/transferFrom/approve; anySelector would move value untracked.
            if (anySelector && _hasTokenLimit(config, scope.target)) {
                revert AnySelectorOnLimitedToken(scope.target);
            }

            for (uint256 j; j < scope.selectorRules.length; j++) {
                SelectorRule memory rule = scope.selectorRules[j];
                for (uint256 d; d < j; d++) {
                    if (scope.selectorRules[d].selector == rule.selector) {
                        revert DuplicateSelectorRule(scope.target, rule.selector);
                    }
                }
                // A recipient allowlist is only enforceable for selectors whose recipient argument we can decode.
                if (rule.recipients.length > 0 && !_isErc20Selector(rule.selector)) {
                    revert RecipientRuleUnsupportedSelector(rule.selector);
                }
            }
        }
    }

    /// @dev Consumes `amount` against a token's cap; skips zero amounts. Reverts with ExceededAllowance when the
    ///      cumulative period spend exceeds the cap.
    function _consume(bytes32 commitment, address token, uint160 allowance, uint40 period, uint256 amount) internal {
        if (amount == 0) return;
        _usage.useLimit(
            _spendKey(commitment, token),
            RecurringAllowance.Limit({allowance: allowance, period: period, start: 0, end: type(uint40).max}),
            amount
        );
    }

    /// @dev Derives the per-(binding, token) usage key so each token's spend accounting is isolated per commitment.
    function _spendKey(bytes32 commitment, address token) internal pure returns (bytes32) {
        return keccak256(abi.encode(commitment, token));
    }

    /// @dev True if `config` pins a spend limit for `token`.
    function _hasTokenLimit(Config memory config, address token) internal pure returns (bool) {
        for (uint256 i; i < config.tokenLimits.length; i++) {
            if (config.tokenLimits[i].token == token) return true;
        }
        return false;
    }

    /// @dev Finds the spend cap for `token` (period normalized). Reverts with LimitTooLarge if a limit exceeds
    ///      uint160 (defensive; {_validateConfig} already rejects it).
    function _findTokenLimit(Config memory config, address token)
        internal
        pure
        returns (bool set, uint160 allowance, uint40 period)
    {
        for (uint256 i; i < config.tokenLimits.length; i++) {
            TokenLimit memory tl = config.tokenLimits[i];
            if (tl.token == token) {
                // Defensive: never truncate a >uint160 limit if {_validateConfig}'s check is ever bypassed.
                if (tl.limit > type(uint160).max) revert LimitTooLarge(tl.token, tl.limit);
                return (true, uint160(tl.limit), tl.period == 0 ? ONE_TIME_PERIOD : tl.period);
            }
        }
        return (false, 0, 0);
    }

    /// @dev Finds the {CallScope} for `target`, reporting whether it was found and whether it pins no selectors.
    function _findScope(Config memory config, address target)
        internal
        pure
        returns (bool allowed, bool anySelector, CallScope memory scope)
    {
        for (uint256 i; i < config.callScopes.length; i++) {
            if (config.callScopes[i].target == target) {
                scope = config.callScopes[i];
                return (true, scope.selectorRules.length == 0, scope);
            }
        }
        return (false, false, scope);
    }

    /// @dev Finds the {SelectorRule} for `selector` within `scope`, returning its recipient allowlist if any.
    function _findSelectorRule(CallScope memory scope, bytes4 selector)
        internal
        pure
        returns (bool allowed, bool recipientBound, address[] memory recipients)
    {
        for (uint256 j; j < scope.selectorRules.length; j++) {
            SelectorRule memory rule = scope.selectorRules[j];
            if (rule.selector == selector) {
                return (true, rule.recipients.length > 0, rule.recipients);
            }
        }
        return (false, false, recipients);
    }

    /// @dev True if `recipient` is in `recipients`.
    function _recipientIn(address[] memory recipients, address recipient) internal pure returns (bool) {
        for (uint256 i; i < recipients.length; i++) {
            if (recipients[i] == recipient) return true;
        }
        return false;
    }

    /// @dev True for the standard ERC-20 selectors this policy can decode for recipient + amount semantics.
    function _isErc20Selector(bytes4 selector) internal pure returns (bool) {
        return selector == TRANSFER || selector == TRANSFER_FROM || selector == APPROVE;
    }

    /// @dev Reads the leading 4-byte selector from `data` (caller guarantees length >= 4), masked to a clean bytes4.
    function _selectorOf(bytes memory data) internal pure returns (bytes4 selector) {
        assembly ("memory-safe") {
            selector := and(mload(add(data, 0x20)), shl(224, 0xffffffff))
        }
    }

    /// @dev Decodes (recipient, amount) from a supported ERC-20 call (`recipient` is `to`, or `spender` for
    ///      approve). Reverts with MalformedTokenCall when the calldata is too short.
    function _decodeErc20(bytes4 selector, bytes memory data)
        internal
        pure
        returns (address recipient, uint256 amount)
    {
        uint256 recipientWord;
        if (selector == TRANSFER || selector == APPROVE) {
            // transfer(address to, uint256 amount) / approve(address spender, uint256 amount).
            if (data.length < 4 + 64) revert MalformedTokenCall(selector);
            assembly ("memory-safe") {
                recipientWord := mload(add(data, 0x24))
                amount := mload(add(data, 0x44))
            }
        } else {
            // transferFrom(address from, address to, uint256 amount): recipient = to.
            if (data.length < 4 + 96) revert MalformedTokenCall(selector);
            assembly ("memory-safe") {
                recipientWord := mload(add(data, 0x44))
                amount := mload(add(data, 0x64))
            }
        }
        // Truncate to the low 160 bits: ABI pads the high bytes, but a caller could dirty them.
        recipient = address(uint160(recipientWord));
    }

    /// @dev Decodes the `from` (source) address of a `transferFrom` call. Reverts with MalformedTokenCall when the
    ///      calldata is too short.
    function _decodeTransferFromSender(bytes memory data) internal pure returns (address from) {
        if (data.length < 4 + 96) revert MalformedTokenCall(TRANSFER_FROM);
        uint256 fromWord;
        assembly ("memory-safe") {
            fromWord := mload(add(data, 0x24))
        }
        // Truncate to the low 160 bits: ABI pads the high bytes, but a caller could dirty them.
        from = address(uint160(fromWord));
    }
}
