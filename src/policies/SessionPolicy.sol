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
///      Storage model: the committed {Config} is decoded once in {onInstall} and flattened into commitment-keyed
///      mappings, so {onExecute} resolves every check with O(1) SLOADs (no array scans). Per-call cost therefore
///      tracks the constraints actually configured.
///
///      Selector awareness (the one inherent limitation): recipient allowlists and spend-limit accounting require
///      decoding the call's arguments, which is only possible for selectors whose ABI layout is known. This policy
///      hardcodes the standard ERC-20 set — `transfer`, `transferFrom`, `approve`. Consequences:
///        - A recipient allowlist may only be attached to one of those selectors (enforced at install).
///        - Spend limits are consumed only for those selectors when called on a limited token (`approve` included,
///          so an allowance grant cannot exceed the remaining budget). `anySelector` on a limited token is rejected
///          at install; pin an explicit selector allowlist instead.
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

    // ── Committed configuration (what the account signs; decoded once at install) ──

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

    // ── Flattened storage (populated in onInstall, read in onExecute) ──

    /// @dev Per-target scope: whether the target is allowed and whether any selector is permitted on it.
    struct TargetScope {
        bool allowed;
        bool anySelector;
    }

    /// @dev Per-selector rule on a target: whether allowed and whether a recipient allowlist applies.
    struct SelRule {
        bool allowed;
        bool recipientBound;
    }

    /// @dev Per-token spend cap (normalized): set flag, uint160 allowance, and period (0-config => uint40 max).
    struct TokenSpend {
        bool set;
        uint160 allowance;
        uint40 period;
    }

    /// @dev commitment => target => scope.
    mapping(bytes32 commitment => mapping(address target => TargetScope)) internal _targetScope;
    /// @dev commitment => target => selector => rule.
    mapping(bytes32 commitment => mapping(address target => mapping(bytes4 selector => SelRule))) internal
        _selectorRule;
    /// @dev commitment => target => selector => recipient => allowed.
    mapping(
        bytes32 commitment
            => mapping(address target => mapping(bytes4 selector => mapping(address recipient => bool allowed)))
    ) internal _recipientAllowed;
    /// @dev commitment => token (address(0) = native) => spend cap.
    mapping(bytes32 commitment => mapping(address token => TokenSpend)) internal _tokenSpend;
    /// @dev Recurring-allowance usage, keyed by keccak256(commitment, token).
    RecurringAllowance.State internal _usage;

    // ── ERC-20 selectors this policy can decode for recipient + amount semantics ──

    bytes4 internal constant TRANSFER = IERC20.transfer.selector; // transfer(address,uint256)
    bytes4 internal constant TRANSFER_FROM = IERC20.transferFrom.selector; // transferFrom(address,address,uint256)
    bytes4 internal constant APPROVE = IERC20.approve.selector; // approve(address,uint256)

    /// @dev One-time limits are modeled as a never-resetting window: period is stored as type(uint40).max and the
    ///      window spans [0, max], so the cumulative spend simply never refreshes within representable time.
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
    /// @notice A configured spend limit was zero, which would be a no-op cap; reject at install to fail closed.
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
    ///         batch that bypasses every policy check. Reject at install to fail closed.
    error SelfTargetNotAllowed();
    /// @notice A `transferFrom` moved funds from an address other than the account. A session key may only spend the
    ///         account's own resources, not third-party allowances the account happens to hold.
    error TransferFromNotSelf(address from);

    constructor(address policyManager) Policy(policyManager) {}

    // ── Views ──

    /// @notice Returns the committed target scope for a binding: whether the target is allowed at all, and whether
    ///         any selector is permitted on it (i.e. no explicit selector allowlist was configured).
    ///
    /// @param commitment The installed binding's commitment.
    /// @param target     The call target to resolve.
    ///
    /// @return allowed     True if `target` is in the binding's call-target allowlist.
    /// @return anySelector True if any selector is permitted on `target` (no per-selector gating).
    function isTargetAllowed(bytes32 commitment, address target)
        external
        view
        returns (bool allowed, bool anySelector)
    {
        TargetScope storage s = _targetScope[commitment][target];
        return (s.allowed, s.anySelector);
    }

    /// @notice Returns the committed selector rule for a `(target, selector)` pair: whether the selector is allowed
    ///         and whether a recipient allowlist applies to it.
    ///
    /// @param commitment The installed binding's commitment.
    /// @param target     The call target the selector rule belongs to.
    /// @param selector   The 4-byte function selector to resolve.
    ///
    /// @return allowed        True if `selector` is permitted on `target`.
    /// @return recipientBound True if a recipient allowlist is enforced for this selector.
    function getSelectorRule(bytes32 commitment, address target, bytes4 selector)
        external
        view
        returns (bool allowed, bool recipientBound)
    {
        SelRule storage r = _selectorRule[commitment][target][selector];
        return (r.allowed, r.recipientBound);
    }

    /// @notice Returns whether `recipient` is in the committed recipient allowlist for a `(target, selector)` pair.
    ///
    /// @param commitment The installed binding's commitment.
    /// @param target     The call target the selector rule belongs to.
    /// @param selector   The 4-byte function selector the allowlist is attached to.
    /// @param recipient  The recipient address to check.
    ///
    /// @return True if `recipient` is allowed for `selector` on `target`.
    function isRecipientAllowed(bytes32 commitment, address target, bytes4 selector, address recipient)
        external
        view
        returns (bool)
    {
        return _recipientAllowed[commitment][target][selector][recipient];
    }

    /// @notice Returns the committed spend cap for a token (or native ETH via `token == address(0)`).
    ///
    /// @param commitment The installed binding's commitment.
    /// @param token      ERC-20 token address, or address(0) for the native-ETH cap.
    ///
    /// @return set       True if a spend cap is configured for `token`.
    /// @return allowance The per-period spend cap (normalized to uint160).
    /// @return period    The recurring period in seconds, or {ONE_TIME_PERIOD} for a one-time (never-resetting) cap.
    function getTokenLimit(bytes32 commitment, address token)
        external
        view
        returns (bool set, uint160 allowance, uint40 period)
    {
        TokenSpend storage t = _tokenSpend[commitment][token];
        return (t.set, t.allowance, t.period);
    }

    /// @notice Returns the current-period spend usage for a token's cap under a binding.
    ///
    /// @dev Reflects the remaining budget for the active window: the returned {RecurringAllowance.PeriodUsage} carries
    ///      the period bounds and the amount already spent within them.
    ///
    /// @param commitment The installed binding's commitment.
    /// @param token      ERC-20 token address, or address(0) for the native-ETH cap.
    ///
    /// @return The current period's usage snapshot (window bounds and spend so far).
    function getCurrentSpend(bytes32 commitment, address token)
        external
        view
        returns (RecurringAllowance.PeriodUsage memory)
    {
        TokenSpend storage t = _tokenSpend[commitment][token];
        return _usage.getCurrentPeriod(_spendKey(commitment, token), _limitOf(t));
    }

    // ── Hooks ──

    /// @dev Decodes the committed {Config} once and flattens it into the commitment-keyed lookup mappings that
    ///      {_onExecute} reads. Validates and normalizes every spend cap (rejects {ZeroLimit} and {LimitTooLarge},
    ///      folds a zero period into {ONE_TIME_PERIOD}); for each call scope records the target (rejecting
    ///      {AnySelectorOnLimitedToken} when a limited token would be left with untracked selectors) and, per
    ///      selector rule, whether a recipient allowlist applies (rejecting {RecipientRuleUnsupportedSelector} for a
    ///      selector whose recipient cannot be decoded) plus the recipient set itself.
    function _onInstall(bytes32 commitment, address account, bytes calldata policyConfig) internal override {
        Config memory config = abi.decode(policyConfig, (Config));

        for (uint256 i; i < config.tokenLimits.length; i++) {
            TokenLimit memory tl = config.tokenLimits[i];
            if (tl.limit == 0) revert ZeroLimit(tl.token);
            if (tl.limit > type(uint160).max) revert LimitTooLarge(tl.token, tl.limit);
            _tokenSpend[commitment][tl.token] = TokenSpend({
                set: true, allowance: uint160(tl.limit), period: tl.period == 0 ? ONE_TIME_PERIOD : tl.period
            });
        }

        for (uint256 i; i < config.callScopes.length; i++) {
            CallScope memory scope = config.callScopes[i];
            // Fail closed: the account is always authorized to call its own executeBatch, so a session key allowed to
            // target the account could re-enter with an arbitrary, unchecked batch and escape every policy dimension.
            if (scope.target == account) revert SelfTargetNotAllowed();
            bool anySelector = scope.selectorRules.length == 0;
            // Fail closed: a TokenLimit on this target only tracks transfer/transferFrom/approve, so anySelector
            // would let other methods move value untracked. Require an explicit selector allowlist instead.
            if (anySelector && _tokenSpend[commitment][scope.target].set) {
                revert AnySelectorOnLimitedToken(scope.target);
            }
            _targetScope[commitment][scope.target] = TargetScope({allowed: true, anySelector: anySelector});

            for (uint256 j; j < scope.selectorRules.length; j++) {
                SelectorRule memory rule = scope.selectorRules[j];
                bool recipientBound = rule.recipients.length > 0;
                // A recipient allowlist is only enforceable for selectors whose recipient argument we can decode.
                if (recipientBound && !_isErc20Selector(rule.selector)) {
                    revert RecipientRuleUnsupportedSelector(rule.selector);
                }
                _selectorRule[commitment][scope.target][rule.selector] =
                    SelRule({allowed: true, recipientBound: recipientBound});
                for (uint256 k; k < rule.recipients.length; k++) {
                    _recipientAllowed[commitment][scope.target][rule.selector][rule.recipients[k]] = true;
                }
            }
        }
    }

    /// @dev Enforces every configured dimension against a single decoded {Action} atomically, then returns the
    ///      account call plan. In order: the target allowlist ({TargetNotAllowed}); for calls carrying a selector,
    ///      the per-target selector allowlist ({SelectorNotAllowed}) and, when bound, the recipient allowlist
    ///      ({RecipientNotAllowed}); the ERC-20 spend cap for decodable spend selectors on a limited token; and the
    ///      native-ETH spend cap consumed from the call `value`. Calldata of 1–3 bytes is rejected ({MissingSelector}).
    ///      On success returns the `executeBatch` calldata for a single {Call} mirroring the action.
    function _onExecute(bytes32 commitment, address account, bytes calldata executionData, address)
        internal
        override
        returns (bytes memory accountCallData)
    {
        Action memory action = abi.decode(executionData, (Action));

        // 1. Target allowlist.
        TargetScope storage scope = _targetScope[commitment][action.target];
        if (!scope.allowed) revert TargetNotAllowed(action.target);

        // 2. Selector + recipient gating (for calls carrying a selector).
        if (action.data.length >= 4) {
            bytes4 selector = _selectorOf(action.data);

            if (!scope.anySelector) {
                SelRule storage rule = _selectorRule[commitment][action.target][selector];
                if (!rule.allowed) revert SelectorNotAllowed(action.target, selector);
                if (rule.recipientBound) {
                    (address recipient,) = _decodeErc20(selector, action.data);
                    if (!_recipientAllowed[commitment][action.target][selector][recipient]) {
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
                TokenSpend storage tokenCap = _tokenSpend[commitment][action.target];
                if (tokenCap.set) {
                    (, uint256 amount) = _decodeErc20(selector, action.data);
                    _consume(commitment, action.target, tokenCap, amount);
                }
            }
        } else if (action.data.length != 0) {
            // 1–3 bytes of data carry no usable selector; reject rather than guess.
            revert MissingSelector();
        }

        // 3b. Native-ETH spend limit: consume from the call value, independent of calldata.
        if (action.value > 0) {
            TokenSpend storage nativeCap = _tokenSpend[commitment][address(0)];
            if (nativeCap.set) _consume(commitment, address(0), nativeCap, action.value);
        }

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: action.target, value: action.value, data: action.data});
        return abi.encodeCall(DefaultAccount.executeBatch, (calls));
    }

    // ── Internal helpers ──

    /// @dev Consume `amount` against a token's cap. Skips zero amounts (the library rejects zero-value spends).
    function _consume(bytes32 commitment, address token, TokenSpend storage cap, uint256 amount) internal {
        if (amount == 0) return;
        _usage.useLimit(_spendKey(commitment, token), _limitOf(cap), amount);
    }

    function _limitOf(TokenSpend storage cap) internal view returns (RecurringAllowance.Limit memory) {
        // start/end are fixed: the window opens at epoch 0 and never closes within representable time, so the
        // manager's validAfter/validUntil remains the sole validity gate and this tracks only spend.
        return RecurringAllowance.Limit({allowance: cap.allowance, period: cap.period, start: 0, end: type(uint40).max});
    }

    /// @dev Derives the per-(binding, token) usage key so each token's spend accounting is isolated per commitment.
    function _spendKey(bytes32 commitment, address token) internal pure returns (bytes32) {
        return keccak256(abi.encode(commitment, token));
    }

    /// @dev True for the standard ERC-20 selectors this policy can decode for recipient + amount semantics.
    function _isErc20Selector(bytes4 selector) internal pure returns (bool) {
        return selector == TRANSFER || selector == TRANSFER_FROM || selector == APPROVE;
    }

    /// @dev Reads the leading 4-byte selector from `data` (caller guarantees `data.length >= 4`).
    function _selectorOf(bytes memory data) internal pure returns (bytes4 selector) {
        assembly ("memory-safe") {
            selector := mload(add(data, 0x20))
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
