// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Call, DefaultAccount} from "./DefaultAccount.sol";

/// @notice High-rate sponsoring account variant for EIP-8130.
///
///         Intended for accounts that sponsor transactions at a high rate. Because outbound ETH value
///         transfers are blocked while the account is locked, the only ETH decrease is gas fees — giving
///         mempools maximum balance predictability and enabling higher rate limits for sponsored txs.
///
///         Deployed behind a plain 45-byte ERC-1167 minimal proxy: each account is an ERC-1167 clone that
///         delegatecalls this shared implementation. That fixed delegation (hardcoded implementation
///         address) is what allows the account to be admitted for high-rate sponsoring.
contract DefaultHighRateSponsoringAccount is DefaultAccount {
    /// @notice A value-bearing call was attempted while the account is locked.
    error AccountLocked();

    constructor(address accountConfiguration) DefaultAccount(accountConfiguration) {}

    /// @notice Executes a batch of calls from the account, blocking outbound value transfers while locked.
    ///
    /// @dev Reverts with UnauthorizedCaller when the caller is neither the account nor a TRUSTED_EXECUTOR actor.
    /// @dev Reverts with AccountLocked when a call carries non-zero value and the account is locked.
    /// @dev Reverts with CallFailed when any inner call reverts.
    ///
    /// @param calls Ordered calls to execute, each as (target, value, data).
    function executeBatch(Call[] calldata calls) external override {
        if (!_isAuthorizedCaller(msg.sender)) revert UnauthorizedCaller();
        for (uint256 i; i < calls.length; i++) {
            if (calls[i].value > 0) {
                (bool locked,,,) = ACCOUNT_CONFIGURATION.getLockStatus(address(this));
                if (locked) revert AccountLocked();
            }
            (bool success,) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!success) revert CallFailed();
        }
    }
}
