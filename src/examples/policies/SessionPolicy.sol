// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";

import {Call, DefaultAccount} from "../../accounts/DefaultAccount.sol";
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
///        - Spend limits are consumed only for those selectors when called on a limited token; other selectors on
///          a token are governed solely by target/selector gating. To prevent untracked token movement, simply do
///          not allow non-spend selectors on a limited token via the selector rules.
///        - Native-ETH limits are consumed from each call's `value`, independent of calldata.
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

    error TargetNotAllowed(address target);
    error SelectorNotAllowed(address target, bytes4 selector);
    error RecipientNotAllowed(address target, bytes4 selector, address recipient);
    error MissingSelector();
    error LimitTooLarge(address token, uint256 limit);
    error ZeroLimit(address token);
    error RecipientRuleUnsupportedSelector(bytes4 selector);
    error MalformedTokenCall(bytes4 selector);

    constructor(address policyManager) Policy(policyManager) {}

    // ── Views ──

    function isTargetAllowed(bytes32 commitment, address target)
        external
        view
        returns (bool allowed, bool anySelector)
    {
        TargetScope storage s = _targetScope[commitment][target];
        return (s.allowed, s.anySelector);
    }

    function getSelectorRule(bytes32 commitment, address target, bytes4 selector)
        external
        view
        returns (bool allowed, bool recipientBound)
    {
        SelRule storage r = _selectorRule[commitment][target][selector];
        return (r.allowed, r.recipientBound);
    }

    function isRecipientAllowed(bytes32 commitment, address target, bytes4 selector, address recipient)
        external
        view
        returns (bool)
    {
        return _recipientAllowed[commitment][target][selector][recipient];
    }

    function getTokenLimit(bytes32 commitment, address token)
        external
        view
        returns (bool set, uint160 allowance, uint40 period)
    {
        TokenSpend storage t = _tokenSpend[commitment][token];
        return (t.set, t.allowance, t.period);
    }

    function getCurrentSpend(bytes32 commitment, address token)
        external
        view
        returns (RecurringAllowance.PeriodUsage memory)
    {
        TokenSpend storage t = _tokenSpend[commitment][token];
        return _usage.getCurrentPeriod(_spendKey(commitment, token), _limitOf(t));
    }

    // ── Hooks ──

    function _onInstall(bytes32 commitment, address, bytes calldata policyConfig) internal override {
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
            bool anySelector = scope.selectorRules.length == 0;
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

    function _onExecute(bytes32 commitment, address, bytes calldata executionData, address)
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

            // 3a. ERC-20 spend limit: consume the target token's cap for decodable spend selectors.
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

    function _spendKey(bytes32 commitment, address token) internal pure returns (bytes32) {
        return keccak256(abi.encode(commitment, token));
    }

    function _isErc20Selector(bytes4 selector) internal pure returns (bool) {
        return selector == TRANSFER || selector == TRANSFER_FROM || selector == APPROVE;
    }

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
}
