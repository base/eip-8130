// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {LibCall} from "solady/utils/LibCall.sol";

import {Call, DefaultAccount} from "./DefaultAccount.sol";

/// @notice Canonical high-rate payer account variant for EIP-8130.
///
///         Intended for accounts that pay gas at a high rate — either sponsoring other txs or
///         transacting themselves. While locked, outbound ETH value transfers are blocked — the
///         account cannot move its own ETH in the transaction — so the only balance decrease is gas
///         fees. That predictability lets mempools admit higher payer rate limits.
///
///         Deployed behind a plain 45-byte ERC-1167 minimal proxy: each account is an ERC-1167 clone that
///         delegatecalls this shared implementation. That fixed delegation (hardcoded implementation
///         address) is what allows the account to be admitted as a high-rate payer.
///
/// @dev STRAWMAN (pre-PPS): the lock that backs payer-tier balance predictability now lives ENTIRELY in this
///      allowlisted account implementation — it is no longer a Keystore concept. Keystore's account-wide lock was
///      removed; sender-tier front-run safety is a per-actor {Keystore.ActorConfig} revoke delay. Because nodes
///      already have to allowlist this bytecode to grant the payer tier, they can read this contract's own lock slot
///      (layout documented at {getPayerLockStatus}) — enshrining the ETH-movement restriction in the system contract
///      is unnecessary. This keeps Keystore agnostic to any one account variant's balance-predictability needs.
///
/// @author Coinbase
contract CanonicalHighRatePayerAccount is DefaultAccount {
    /// @notice Self-contained payer lock. Packs into a single storage slot (slot 0 of the clone): a node that has
    ///         allowlisted this implementation reads that slot directly for payer-tier admission.
    ///
    /// @dev `unlockDelay` is the configured delay (seconds) applied when an unlock is initiated; `unlocksAt` is the
    ///      timestamp a pending unlock takes effect. While `unlockInitiated` is clear, `unlocksAt` is unused (0).
    struct PayerLock {
        bool locked; // the account is in payer-lock (ETH-out blocked) unless a pending unlock has elapsed
        bool unlockInitiated; // an unlock has been initiated; `unlocksAt` governs
        uint32 unlockDelay; // configured unlock delay in seconds
        uint48 unlocksAt; // timestamp at which the pending unlock takes effect
    }

    /// @notice The account's payer-lock state (slot 0). Read by nodes for payer-tier rate-limit admission.
    PayerLock internal _payerLock;

    /// @notice A value-bearing call was attempted while the account is locked.
    error AccountLocked();

    /// @notice A lock op carried a zero unlock delay.
    error ZeroUnlockDelay();

    /// @notice A lock op was attempted while the account was already locked.
    error AccountAlreadyLocked();

    /// @notice An unlock op was attempted when the account was not hard-locked (never locked, or unlock already
    ///         initiated).
    error NotLocked();

    /// @notice Emitted when the account is locked.
    /// @param unlockDelay The configured unlock delay in seconds.
    event PayerLocked(uint32 unlockDelay);

    /// @notice Emitted when the account's unlock is initiated.
    /// @param unlocksAt The timestamp at which the account will unlock.
    event AccountUnlockInitiated(uint48 unlocksAt);

    constructor(address keystore) DefaultAccount(keystore) {}

    // ══════════════════════════════════════════════
    //  PAYER LOCK
    // ══════════════════════════════════════════════

    /// @notice Locks the account into payer mode: outbound ETH value transfers are blocked until a later unlock
    ///         delay elapses. Callable by any authorized caller (the account itself or a TRUSTED_EXECUTOR operator).
    ///
    /// @dev STRAWMAN (pre-PPS): authorization reuses {_isAuthorizedCaller}. A production design may want to gate the
    ///      unlock path to the admin (scope 0) specifically, since unlocking removes the balance-predictability
    ///      guarantee the payer tier relies on.
    /// @dev Reverts with ZeroUnlockDelay when `unlockDelay` is 0.
    /// @dev Reverts with AccountAlreadyLocked when the account is already locked.
    ///
    /// @param unlockDelay The delay (seconds) that a later {initiateUnlock} must wait out before ETH transfers resume.
    function lock(uint32 unlockDelay) external {
        if (!_isAuthorizedCaller(msg.sender)) revert UnauthorizedCaller();
        if (unlockDelay == 0) revert ZeroUnlockDelay();
        if (_isLocked()) revert AccountAlreadyLocked();
        _payerLock = PayerLock({locked: true, unlockInitiated: false, unlockDelay: unlockDelay, unlocksAt: 0});
        emit PayerLocked(unlockDelay);
    }

    /// @notice Initiates an unlock: after the configured delay elapses the account leaves payer mode and can move ETH
    ///         again. Callable by any authorized caller.
    ///
    /// @dev Reverts with NotLocked when the account is not hard-locked (never locked, or an unlock is already pending).
    function initiateUnlock() external {
        if (!_isAuthorizedCaller(msg.sender)) revert UnauthorizedCaller();
        PayerLock storage l = _payerLock;
        if (!l.locked || l.unlockInitiated) revert NotLocked();
        uint48 unlocksAt = uint48(block.timestamp + l.unlockDelay);
        l.unlockInitiated = true;
        l.unlocksAt = unlocksAt;
        emit AccountUnlockInitiated(unlocksAt);
    }

    /// @notice Whether the account is currently in payer lock (ETH-out blocked).
    function isLocked() external view returns (bool) {
        return _isLocked();
    }

    /// @notice The account's full payer-lock status, for nodes deciding payer-tier admission.
    ///
    /// @dev A node grants the higher payer tier when `locked && !hasInitiatedUnlock && unlockDelay >= threshold`,
    ///      mirroring the old Keystore Account Lock read but against this account's own slot 0.
    ///
    /// @return locked True if the account is locked at the current block timestamp.
    /// @return hasInitiatedUnlock True if an unlock has been initiated but not yet elapsed.
    /// @return unlocksAt The timestamp at which the account unlocks (type(uint48).max while hard-locked).
    /// @return unlockDelay The configured unlock delay in seconds.
    function getPayerLockStatus()
        external
        view
        returns (bool locked, bool hasInitiatedUnlock, uint48 unlocksAt, uint32 unlockDelay)
    {
        PayerLock storage l = _payerLock;
        if (!l.locked) {
            return (false, false, 0, 0);
        }
        if (!l.unlockInitiated) {
            return (true, false, type(uint48).max, l.unlockDelay);
        }
        if (block.timestamp >= l.unlocksAt) {
            return (false, false, 0, 0);
        }
        return (true, true, l.unlocksAt, 0);
    }

    /// @dev True while the account's ETH is frozen: locked, unless a pending unlock's timestamp has elapsed.
    function _isLocked() internal view returns (bool) {
        PayerLock storage l = _payerLock;
        if (!l.locked) return false;
        if (!l.unlockInitiated) return true;
        return block.timestamp < l.unlocksAt;
    }

    // ══════════════════════════════════════════════
    //  EXECUTION
    // ══════════════════════════════════════════════

    /// @notice Executes a batch of calls from the account, blocking outbound value transfers while locked.
    ///
    /// @dev Reverts with UnauthorizedCaller when the caller is neither the account nor a TRUSTED_EXECUTOR actor.
    /// @dev Reverts with AccountLocked when a call carries non-zero value and the account is locked.
    /// @dev Bubbles up the inner call's revert reason verbatim (a reason-less revert propagates as an empty revert).
    ///
    /// @param calls Ordered calls to execute, each as (target, value, data).
    function executeBatch(Call[] calldata calls) external override {
        if (!_isAuthorizedCaller(msg.sender)) revert UnauthorizedCaller();
        for (uint256 i; i < calls.length; i++) {
            if (calls[i].value > 0 && _isLocked()) revert AccountLocked();
            (bool success, bytes memory result) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!success) LibCall.bubbleUpRevert(result);
        }
    }

    /// @notice Executes a single call from the account, blocking an outbound value transfer while locked.
    ///
    /// @dev Equivalent to a one-element {executeBatch}. Included for selector-compatibility with common existing wallet implementations.
    /// @dev Reverts with UnauthorizedCaller when the caller is neither the account nor a TRUSTED_EXECUTOR actor.
    /// @dev Reverts with AccountLocked when the call carries non-zero value and the account is locked.
    /// @dev Bubbles up the inner call's revert reason verbatim (a reason-less revert propagates as an empty revert).
    ///
    /// @param target Address the account calls.
    /// @param value Wei forwarded with the call.
    /// @param data Calldata passed to `target`.
    function execute(address target, uint256 value, bytes calldata data) external override {
        if (!_isAuthorizedCaller(msg.sender)) revert UnauthorizedCaller();
        if (value > 0 && _isLocked()) revert AccountLocked();
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) LibCall.bubbleUpRevert(result);
    }
}
