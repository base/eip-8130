// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";

import {Call, DefaultAccount} from "../accounts/DefaultAccount.sol";
import {Policy} from "./Policy.sol";
import {RecurringAllowance} from "./RecurringAllowance.sol";

/// @title SessionPolicy
///
/// @notice Unified EIP-8130 "session key" policy combining, in a single committed binding and a single per-call
///         check: a call-target allowlist, per-target function-selector allowlists, per-asset recipient allowlists,
///         and per-token (and native-ETH) recurring/one-time spend limits.
///
/// @dev A single policy (rather than several composed) because {PolicyManager} validates one (policy, commitment)
///      per call; bundling every dimension here lets them all gate the same call atomically.
///
///      Config model: no config storage. Every {onExecute} receives the config preimage via calldata;
///      {PolicyManager} authenticates it by recomputing the binding commitment against Keystore. Config shape checks
///      (ZeroLimit, LimitTooLarge, SelfTargetNotAllowed, duplicates) run at execute via {_validateConfig}.
///      {_findTokenLimit} still defensively re-checks LimitTooLarge before the uint160 cast. The only storage is
///      {_usage} (mutable spend accounting).
///
///      {TokenLimit} is the primary spend grant. Adding a {TokenLimit} for a token both caps that token and, by
///      itself, authorizes the key to move it via the three tracked ERC-20 selectors. Access is resolved per call:
///        - Case 1 — a {TokenLimit} with NO matching {CallScope}: the key may call `transfer`, `transferFrom`,
///          `approve` on that token (only those three), each debited from the cap and gated by the limit's
///          `recipients`. Nothing else on the token is callable.
///        - Case 2 — a {TokenLimit} plus a {CallScope} with an empty selector list (anySelector): the key may call
///          ANY selector on the token. The three tracked selectors are still debited/recipient-gated; every other
///          selector is allowed but NOT debited. This is an explicit opt-in to untracked, value-moving methods
///          (e.g. `increaseAllowance`, ERC-4626 `withdraw`) — use it only when you accept the cap does not bound them.
///        - Case 3 — a {TokenLimit} plus a {CallScope} with an explicit selector list: the key may call exactly the
///          listed selectors. Listed tracked selectors are debited/recipient-gated; listed untracked selectors are
///          allowed but not debited. An explicit list REPLACES the Case-1 default (it does not add to it).
///      A {CallScope} on a target with no {TokenLimit} is a pure call allowlist (no spend semantics).
///
///      Selector awareness (the one inherent limitation): recipient gating and spend accounting require decoding the
///      call's arguments, which is only possible for selectors whose ABI layout is known. This policy hardcodes the
///      standard ERC-20 set — `transfer`, `transferFrom`, `approve`. Only those are debited and recipient-gated;
///      `safeTransferFrom` (ERC-721/1155) and any other value-moving method cannot be decoded (an NFT has no fungible
///      amount, ERC-1155 adds an `id` dimension {TokenLimit} does not carry) and are therefore never tracked — they
///      are reachable only via the explicit Case-2/Case-3 opt-in above.
///
///      Recipients: the recipient allowlist lives on {TokenLimit} (not per-selector) and is the set of allowed
///      destinations for that asset's value. For an ERC-20 it gates the decoded destination of the tracked selectors
///      (`to` for transfer/transferFrom, `spender` for approve — a deliberate merge: an address trusted to receive is
///      trusted to be approved). For native ETH (`token == address(0)`) it gates the call's `target`. Empty = any
///      recipient.
///
///      Approvals vs. periods: `approve` is debited from the *current* period at grant time, but an ERC-20 allowance
///      is standing on-chain state that outlives the period and is pulled by a third party this policy never sees. A
///      grantee can therefore pull a still-live approval from an earlier period in the same wall-clock window as a
///      fresh-period `transfer`, so real token outflow across a period boundary can exceed a single period's cap.
///      Per-period accounting is exact for the key's own actions; it cannot bound reuse of standing allowances.
///
///      Native value fails closed: a call carrying `value` reverts ({NativeValueNotAllowed}) unless the config pins a
///      native {TokenLimit} (`token == address(0)`). Absence means "no ETH", not "unlimited ETH" — so a grant can
///      call a value-accepting target while sending it zero ETH, and this does not depend on the target rejecting
///      value. The resulting asymmetry with ERC-20 defaults is structural: an ERC-20 must be called at its own
///      address to move, so the target allowlist already gates it, whereas native value rides on any call. Both share
///      the same expressible states — forbidden, capped, and unlimited (`limit == type(uint160).max`).
///
///      Calldata length: empty calldata is a plain value transfer (a `receive()`), allowed only against a target with
///      an explicit {CallScope} (a {TokenLimit}-only target is strictly for the three spend selectors, so it cannot
///      receive a bare value transfer); calldata of 1–3 bytes is rejected ({MissingSelector}) as it cannot carry a
///      4-byte selector; 4+ bytes is treated as a selector (so a fallback reachable via 4+ byte data is gated by the
///      selector rules).
contract SessionPolicy is Policy {
    using RecurringAllowance for RecurringAllowance.State;

    // ── Committed configuration (what the account signs; re-supplied at every execute) ──

    /// @notice Per-token (or native-ETH) spend cap and allowed destinations. The primary spend grant.
    struct TokenLimit {
        /// @dev ERC-20 token address, or address(0) for native ETH (gated on each call's `value`).
        address token;
        /// @dev Maximum spend per period (one-time: total cap). Must fit uint160; 0 is rejected ({ZeroLimit}). To
        ///      express an effectively unlimited budget, set `limit = type(uint160).max`.
        uint256 limit;
        /// @dev Recurring period in seconds. 0 = one-time (a single cumulative cap that never resets).
        uint40 period;
        /// @dev Allowed destinations for this asset's value (empty = any). For an ERC-20, gates the decoded recipient
        ///      of the tracked selectors; for native (token == address(0)), gates the call `target`.
        address[] recipients;
    }

    /// @notice A target contract and its allowed selectors.
    struct CallScope {
        /// @dev Target contract this binding may call.
        address target;
        /// @dev Allowed selectors on `target` (empty = any selector allowed).
        bytes4[] selectors;
    }

    /// @notice The full committed configuration for a binding.
    struct Config {
        /// @dev Per-token (and native-ETH) spend caps, and the primary spend grant for each token.
        TokenLimit[] tokenLimits;
        /// @dev Allowed call targets and their selectors.
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

    /// @notice The action's `target` is neither in the call-target allowlist nor a (non-native) limited token, or a
    ///         bare value transfer was attempted against a {TokenLimit}-only target (which permits only the three
    ///         spend selectors, not a plain `receive()`).
    error TargetNotAllowed(address target);

    /// @notice `selector` is not permitted on `target` (a {TokenLimit}-only target permits only the tracked ERC-20
    ///         selectors; an explicit {CallScope} permits only its listed selectors).
    error SelectorNotAllowed(address target, bytes4 selector);

    /// @notice `recipient` (decoded ERC-20 destination, or the call `target` for native) is not in the asset's
    ///         committed recipient allowlist.
    error RecipientNotAllowed(address target, bytes4 selector, address recipient);

    /// @notice The action carried 1–3 bytes of calldata: too short to hold a 4-byte selector, so it is rejected rather
    ///         than guessed.
    error MissingSelector();

    /// @notice A configured spend `limit` exceeds uint160 and cannot be stored in the normalized allowance field.
    error LimitTooLarge(address token, uint256 limit);

    /// @notice A configured spend limit was zero, which would be a no-op cap; reject to fail closed.
    error ZeroLimit(address token);

    /// @notice The action carried native `value` but the config pins no native-ETH limit (`token == address(0)`).
    ///         Native value fails closed: unlike an ERC-20 (which requires calling an allowlisted token contract to
    ///         move), value rides on any call to any allowlisted target, so an absent native limit is treated as "no
    ///         ETH", not "unlimited ETH". To permit ETH, add a native {TokenLimit} with a positive cap.
    error NativeValueNotAllowed(uint256 value);

    /// @notice A supported ERC-20 call's calldata was too short to decode its (recipient, amount) arguments.
    error MalformedTokenCall(bytes4 selector);

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

    /// @notice Duplicate selector within a single call scope.
    error DuplicateSelector(address target, bytes4 selector);

    constructor(address policyManager) Policy(policyManager) {}

    // ── Views (pure over supplied config / explicit limit; no config storage to read) ──

    /// @notice Returns whether `target` is callable by `config`, and whether any selector is permitted on it.
    ///
    /// @dev A target is callable if it has an explicit {CallScope} or a (non-native) {TokenLimit}. `anySelector` is
    ///      true only for an explicit {CallScope} with an empty selector list; a {TokenLimit}-only target permits just
    ///      the three tracked ERC-20 selectors, so it reports `anySelector == false`.
    function isTargetAllowed(Config calldata config, address target)
        external
        pure
        returns (bool allowed, bool anySelector)
    {
        for (uint256 i; i < config.callScopes.length; i++) {
            if (config.callScopes[i].target == target) {
                return (true, config.callScopes[i].selectors.length == 0);
            }
        }
        if (target != address(0)) {
            for (uint256 i; i < config.tokenLimits.length; i++) {
                if (config.tokenLimits[i].token == target) return (true, false);
            }
        }
        return (false, false);
    }

    /// @notice Returns whether `selector` is allowed on `target` by `config`, and whether a recipient allowlist
    ///         applies to it (true only for a tracked ERC-20 selector on a limited token whose limit pins recipients).
    function getSelectorRule(Config calldata config, address target, bytes4 selector)
        external
        pure
        returns (bool allowed, bool recipientBound)
    {
        bool hasScope;
        bool anySelector;
        bool selectorListed;
        for (uint256 i; i < config.callScopes.length; i++) {
            CallScope calldata scope = config.callScopes[i];
            if (scope.target != target) continue;
            hasScope = true;
            anySelector = scope.selectors.length == 0;
            for (uint256 j; j < scope.selectors.length; j++) {
                if (scope.selectors[j] == selector) {
                    selectorListed = true;
                    break;
                }
            }
            break;
        }

        bool hasLimit;
        bool hasRecipients;
        if (target != address(0)) {
            for (uint256 i; i < config.tokenLimits.length; i++) {
                if (config.tokenLimits[i].token == target) {
                    hasLimit = true;
                    hasRecipients = config.tokenLimits[i].recipients.length > 0;
                    break;
                }
            }
        }

        if (hasScope) {
            allowed = anySelector || selectorListed;
        } else {
            allowed = hasLimit && _isErc20Selector(selector);
        }
        recipientBound = allowed && hasLimit && hasRecipients && _isErc20Selector(selector);
    }

    /// @notice Returns whether `recipient` is allowed for `(target, selector)` in `config`. Untracked selectors and
    ///         targets without a recipient-bearing limit are unrestricted (returns true).
    function isRecipientAllowed(Config calldata config, address target, bytes4 selector, address recipient)
        external
        pure
        returns (bool)
    {
        if (!_isErc20Selector(selector)) return true;
        for (uint256 i; i < config.tokenLimits.length; i++) {
            TokenLimit calldata tl = config.tokenLimits[i];
            if (tl.token != target) continue;
            if (tl.recipients.length == 0) return true;
            for (uint256 k; k < tl.recipients.length; k++) {
                if (tl.recipients[k] == recipient) return true;
            }
            return false;
        }
        return true;
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

    /// @notice Returns the committed recipient allowlist for `token` (empty = any recipient / no limit set).
    function getTokenRecipients(Config calldata config, address token)
        external
        pure
        returns (address[] memory recipients)
    {
        for (uint256 i; i < config.tokenLimits.length; i++) {
            if (config.tokenLimits[i].token == token) return config.tokenLimits[i].recipients;
        }
        return new address[](0);
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

        // 1. Resolve the target. It is callable if it has an explicit {CallScope} or a (non-native) {TokenLimit}.
        (bool hasScope, bool anySelector, CallScope memory scope) = _findScope(config, action.target);
        (bool hasLimit, TokenLimit memory limit) = _findTokenLimit(config, action.target);
        // The native sentinel (address(0)) is a value gate, never a call target.
        bool hasErc20Limit = action.target != address(0) && hasLimit;
        if (!hasScope && !hasErc20Limit) revert TargetNotAllowed(action.target);

        // 2. Selector + recipient gating + spend accounting (for calls carrying a selector).
        if (action.data.length >= 4) {
            bytes4 selector = _selectorOf(action.data);

            // Selector access: an explicit {CallScope} governs (any/listed); otherwise a {TokenLimit}-only target
            // permits exactly the three tracked ERC-20 selectors.
            bool selectorAllowed = hasScope ? (anySelector || _selectorIn(scope, selector)) : _isErc20Selector(selector);
            if (!selectorAllowed) revert SelectorNotAllowed(action.target, selector);

            // transferFrom source: a session key spends only the account's own resources, never a third-party
            // allowance the account holds. Enforce `from == account` regardless of limits or recipient rules.
            if (selector == TRANSFER_FROM) {
                address from = _decodeTransferFromSender(action.data);
                if (from != account) revert TransferFromNotSelf(from);
            }

            // Recipient gating + spend accounting: only for decodable ERC-20 selectors on a limited token. `approve`
            // debits at grant time; a standing allowance can still be reused across periods (see contract NatSpec).
            if (hasErc20Limit && _isErc20Selector(selector)) {
                (address recipient, uint256 amount) = _decodeErc20(selector, action.data);
                if (limit.recipients.length > 0 && !_recipientIn(limit.recipients, recipient)) {
                    revert RecipientNotAllowed(action.target, selector, recipient);
                }
                _consume(commitment, action.target, uint160(limit.limit), _period(limit), amount);
            }
        } else if (action.data.length != 0) {
            // 1–3 bytes of data carry no usable selector; reject rather than guess.
            revert MissingSelector();
        } else if (!hasScope) {
            // Empty calldata is a plain value transfer; a {TokenLimit}-only target is strictly for the three spend
            // selectors, so it may not receive a bare value transfer. Require an explicit {CallScope}.
            revert TargetNotAllowed(action.target);
        }

        // 3. Native-ETH spend limit: consume from the call value, independent of calldata. Fail closed — value rides
        // on any call to any allowlisted target, so an absent native limit means "no ETH", not "unlimited ETH".
        if (action.value > 0) {
            (bool nativeSet, TokenLimit memory nativeLimit) = _findTokenLimit(config, address(0));
            if (!nativeSet) revert NativeValueNotAllowed(action.value);
            if (nativeLimit.recipients.length > 0 && !_recipientIn(nativeLimit.recipients, action.target)) {
                revert RecipientNotAllowed(action.target, bytes4(0), action.target);
            }
            _consume(commitment, address(0), uint160(nativeLimit.limit), _period(nativeLimit), action.value);
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
    /// @dev Reverts with DuplicateSelector when a selector appears twice within a call scope.
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
            // Fail closed: the account is always authorized to call its own executeBatch, so a session key allowed to
            // target the account could re-enter with an arbitrary, unchecked batch and escape every policy dimension.
            if (scope.target == account) revert SelfTargetNotAllowed();

            for (uint256 j; j < scope.selectors.length; j++) {
                for (uint256 d; d < j; d++) {
                    if (scope.selectors[d] == scope.selectors[j]) {
                        revert DuplicateSelector(scope.target, scope.selectors[j]);
                    }
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

    /// @dev Normalizes a {TokenLimit} period: 0 (one-time) maps to the never-resetting {ONE_TIME_PERIOD}.
    function _period(TokenLimit memory limit) internal pure returns (uint40) {
        return limit.period == 0 ? ONE_TIME_PERIOD : limit.period;
    }

    /// @dev Finds the {TokenLimit} for `token`, reporting whether one is set. Reverts with LimitTooLarge if its limit
    ///      exceeds uint160 (defensive; {_validateConfig} already rejects it).
    function _findTokenLimit(Config memory config, address token)
        internal
        pure
        returns (bool set, TokenLimit memory limit)
    {
        for (uint256 i; i < config.tokenLimits.length; i++) {
            if (config.tokenLimits[i].token == token) {
                limit = config.tokenLimits[i];
                // Defensive: {_validateConfig} already rejects LimitTooLarge, but never truncate a >uint160 limit into
                // a smaller/arbitrary allowance if that invariant is ever bypassed.
                if (limit.limit > type(uint160).max) revert LimitTooLarge(limit.token, limit.limit);
                return (true, limit);
            }
        }
        return (false, limit);
    }

    /// @dev Finds the {CallScope} for `target`, reporting whether it was found and whether it pins no selectors
    ///      (anySelector).
    function _findScope(Config memory config, address target)
        internal
        pure
        returns (bool allowed, bool anySelector, CallScope memory scope)
    {
        for (uint256 i; i < config.callScopes.length; i++) {
            if (config.callScopes[i].target == target) {
                scope = config.callScopes[i];
                return (true, scope.selectors.length == 0, scope);
            }
        }
        return (false, false, scope);
    }

    /// @dev True if `selector` is listed in `scope`.
    function _selectorIn(CallScope memory scope, bytes4 selector) internal pure returns (bool) {
        for (uint256 j; j < scope.selectors.length; j++) {
            if (scope.selectors[j] == selector) return true;
        }
        return false;
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

    /// @dev Reads the leading 4-byte selector from `data` (caller guarantees length >= 4), masked to a clean bytes4
    ///      so dirty low bytes cannot survive into equality comparisons.
    function _selectorOf(bytes memory data) internal pure returns (bytes4 selector) {
        assembly ("memory-safe") {
            selector := and(mload(add(data, 0x20)), shl(224, 0xffffffff))
        }
    }

    /// @dev Decodes (recipient, amount) from a supported ERC-20 call (`recipient` is `to`, or `spender` for approve).
    ///      Reverts with MalformedTokenCall when the calldata is too short.
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
