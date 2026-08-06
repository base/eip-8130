// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {LibCall} from "solady/utils/LibCall.sol";

import {Call, DefaultAccount} from "./DefaultAccount.sol";

/// @notice Canonical high-rate payer account variant for EIP-8130.
///
///         Intended for accounts that pay gas at a high rate — either sponsoring other txs or
///         transacting themselves. While locked, outbound ETH value transfers are blocked — the
///         account cannot move its own ETH in the transaction — so the only balance decrease is gas
///         fees. That predictability lets mempools admit higher rate limits.
///
///         Deployed behind a plain 45-byte ERC-1167 minimal proxy: each account is an ERC-1167 clone that
///         delegatecalls this shared implementation. That fixed delegation (hardcoded implementation
///         address) is what allows the account to be admitted as a high-rate payer.
contract CanonicalHighRatePayerAccount is DefaultAccount {
    /// @notice A value-bearing call was attempted while the account is locked.
    error AccountLocked();

    constructor(address keystore) DefaultAccount(keystore) {}

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
            if (calls[i].value > 0) {
                (bool locked,,,) = KEYSTORE.getLockStatus(address(this));
                if (locked) revert AccountLocked();
            }
            (bool success, bytes memory result) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!success) LibCall.bubbleUpRevert(result);
        }
    }

    /// @notice Executes a single call from the account, blocking an outbound value transfer while locked.
    ///
    /// @dev Reverts with UnauthorizedCaller when the caller is neither the account nor a TRUSTED_EXECUTOR actor.
    /// @dev Reverts with AccountLocked when the call carries non-zero value and the account is locked.
    /// @dev Bubbles up the inner call's revert reason verbatim (a reason-less revert propagates as an empty revert).
    ///
    /// @param target Address the account calls.
    /// @param value Wei forwarded with the call.
    /// @param data Calldata passed to `target`.
    function execute(address target, uint256 value, bytes calldata data) external override {
        if (!_isAuthorizedCaller(msg.sender)) revert UnauthorizedCaller();
        if (value > 0) {
            (bool locked,,,) = KEYSTORE.getLockStatus(address(this));
            if (locked) revert AccountLocked();
        }
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) LibCall.bubbleUpRevert(result);
    }
}
