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
/// @dev A single policy (rather than several composed) because {PolicyManager} validates one (policy, commitment)
///      per call; bundling every dimension here lets them all gate the same call atomically.
///
///      Config model: no config storage. Every {onExecute} receives the config preimage via calldata;
///      {PolicyManager} authenticates it by recomputing the binding commitment against Keystore.
///      Config shape checks (ZeroLimit, LimitTooLarge, SelfTargetNotAllowed, AnySelectorOnLimitedToken,
///      duplicates, RecipientRuleUnsupportedSelector) run at execute via {_validateConfig}.
///      {_findTokenLimit} still defensively re-checks LimitTooLarge before the uint160 cast. The only storage is
///      {_usage} (mutable spend accounting).
///
///      Selector awareness (the one inherent limitation): recipient allowlists and spend-limit accounting require
///      decoding the call's arguments, which is only possible for selectors whose ABI layout is known. This policy
///      hardcodes the standard ERC-20 set — `transfer`, `transferFrom`, `approve`. Consequences:
///        - A recipient allowlist may only be attached to one of those selectors (enforced at execute).
///        - Spend limits are consumed only for those selectors when called on a limited token (`approve` included,
///          so an allowance grant cannot exceed the remaining budget). `anySelector` on a limited token is rejected
///          at execute; pin an explicit selector allowlist instead.
///        - WARNING: any *other* selector on a limited token is gated by the allowlist but NOT debited from the
///          cap. Value-moving methods this policy cannot decode — e.g. ERC-20 `increaseAllowance`/`decreaseAllowance`,
///          ERC-721 `safeTransferFrom`, any ERC-1155 transfer — therefore bypass the spend cap entirely if listed.
///          Do NOT allow such selectors on a token you are trying to bound; only `transfer`/`transferFrom`/`approve`
///          are tracked.
///        - Native-ETH limits are consumed from each call's `value`, independent of calldata.
///
///      Approvals vs. periods: `approve` is debited from the *current* period at grant time, but an ERC-20 allowance
///      is standing on-chain state that outlives the period and is pulled by a third party this policy never sees. A
///      grantee can therefore pull a still-live approval from an earlier period in the same wall-clock window as a
///      fresh-period `transfer`, so real token outflow across a period boundary can exceed a single period's cap.
///      Per-period accounting is exact for the key's own actions; it cannot bound reuse of standing allowances.
///
///      Calldata length: empty calldata is allowed (a `receive()` / plain value transfer, gated by the target
///      allowlist and native-ETH cap); calldata of 1–3 bytes is rejected ({MissingSelector}) as it cannot carry a
///      4-byte selector; 4+ bytes is treated as a selector (so a fallback reachable via 4+ byte data is gated by the
///      selector rules).
contract SessionPolicy is Policy {
    using RecurringAllowance for RecurringAllowance.State;

    // ── Committed configuration (what the account signs; re-supplied at every execute) ──

    /// @notice Per-token (or native-ETH) spend cap.
    struct TokenLimit {
        /// @dev ERC-20 token address, or address(0) for native ETH (gated on each call's `value`).
        address token;
        /// @dev Maximum spend per period (one-time: total cap). Must fit uint160.
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
        TokenLimit[] tokenLimits;
        CallScope[] callScopes;
    }

    /// @notice Per-use action: a single call the session key wants the account to make.
    struct Action {
        address target;
        uint256 value;
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
    /// @notice A recipient allowlist was attached to a selector whose recipient argument this policy cannot decode
    ///         (only the standard ERC-20 selectors are supported).
    error RecipientRuleUnsupportedSelector(bytes4 selector);
    /// @notice A supported ERC-20 call's calldata was too short to decode its (recipient, amount) arguments.
    error MalformedTokenCall(bytes4 selector);
    /// @notice A limited token must pin its allowed selectors: `anySelector` would let non-ERC20 methods move value
    ///         without debiting the spend cap. Native-ETH limits (`token == address(0)`) are unaffected — they gate
    ///         call `value`, not a call target.
    error AnySelectorOnLimitedToken(address token);
    /// @notice A call scope targeted the account itself. The account is always an authorized caller of its own
    ///         `executeBatch`, so allowing a session key to call it would let the key re-enter with an arbitrary
    ///         batch that bypasses every policy check. Reject to fail closed.
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

    // ── Views (pure over supplied config / explicit limit; no config storage to read) ──

    /// @notice Returns whether `target` is allowed by `config`, and whether any selector is permitted on it.
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
    /// @dev `limit` is unauthenticated calldata — results are only meaningful when `limit` is the committed
    ///      {TokenLimit} from the binding's config (same token/limit/period the account signed).
    ///      `limit.period == 0` is normalized to {ONE_TIME_PERIOD} so the accounting library never sees a zero period.
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

    /// @dev Validates config, enforces every configured dimension against a single decoded {Action} by linear scan,
    ///      then returns the account call plan (and empty postCallData). The manager has already authenticated
    ///      `policyConfig` via the binding commitment.
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

            // 3. transferFrom source: a session key spends only the account's own resources, never a third-party
            // allowance the account holds. Enforce `from == account` regardless of token limits or recipient rules.
            if (selector == TRANSFER_FROM) {
                address from = _decodeTransferFromSender(action.data);
                if (from != account) revert TransferFromNotSelf(from);
            }

            // 3a. ERC-20 spend limit: consume the target token's cap for decodable spend selectors. Note `approve`
            // debits at grant time; a standing allowance can still be reused across periods (see contract NatSpec).
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

        // 3b. Native-ETH spend limit: consume from the call value, independent of calldata.
        if (action.value > 0) {
            (bool set, uint160 allowance, uint40 period) = _findTokenLimit(config, address(0));
            if (set) _consume(commitment, address(0), allowance, period, action.value);
        }

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: action.target, value: action.value, data: action.data});
        return (abi.encodeCall(DefaultAccount.executeBatch, (calls)), "");
    }

    // ── Internal helpers ──

    /// @dev Validates the committed {Config}. Rejects zero/oversized limits, self-targets, anySelector on limited
    ///      tokens, unsupported recipient rules, and duplicates (token / target / selector).
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
            // Fail closed: the account is always authorized to call its own executeBatch, so a session key allowed to
            // target the account could re-enter with an arbitrary, unchecked batch and escape every policy dimension.
            if (scope.target == account) revert SelfTargetNotAllowed();
            bool anySelector = scope.selectorRules.length == 0;
            // Fail closed: a TokenLimit on this target only tracks transfer/transferFrom/approve, so anySelector
            // would let other methods move value untracked. Require an explicit selector allowlist instead.
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

    /// @dev Consume `amount` against a token's cap. Skips zero amounts (the library rejects zero-value spends).
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

    function _hasTokenLimit(Config memory config, address token) internal pure returns (bool) {
        for (uint256 i; i < config.tokenLimits.length; i++) {
            if (config.tokenLimits[i].token == token) return true;
        }
        return false;
    }

    function _findTokenLimit(Config memory config, address token)
        internal
        pure
        returns (bool set, uint160 allowance, uint40 period)
    {
        for (uint256 i; i < config.tokenLimits.length; i++) {
            TokenLimit memory tl = config.tokenLimits[i];
            if (tl.token == token) {
                // Defensive: {_validateConfig} already rejects LimitTooLarge, but never truncate a >uint160 limit
                // into a smaller/arbitrary allowance if that invariant is ever bypassed.
                if (tl.limit > type(uint160).max) revert LimitTooLarge(tl.token, tl.limit);
                return (true, uint160(tl.limit), tl.period == 0 ? ONE_TIME_PERIOD : tl.period);
            }
        }
        return (false, 0, 0);
    }

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

    /// @dev Reads the leading 4-byte selector from `data` (caller guarantees `data.length >= 4`). Masks to a clean
    ///      bytes4 so dirty low bytes cannot survive into equality comparisons.
    function _selectorOf(bytes memory data) internal pure returns (bytes4 selector) {
        assembly ("memory-safe") {
            selector := and(mload(add(data, 0x20)), shl(224, 0xffffffff))
        }
    }

    /// @dev Decode (recipient, amount) for the supported ERC-20 selectors. `recipient` is `to` for transfer /
    ///      transferFrom and `spender` for approve.
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

    /// @dev Decode the `from` (source) address of a `transferFrom(address from, address to, uint256 amount)` call.
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
