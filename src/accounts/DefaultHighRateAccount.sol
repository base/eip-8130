// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Call, DefaultAccount} from "./DefaultAccount.sol";

/// @notice High-rate account variant for EIP-8130.
///
///         Extends the bare DefaultAccount with one additional constraint: blocks outbound ETH value transfers
///         when the account is locked. Combined with lock, ETH balance only decreases through gas fees, giving
///         mempools maximum balance predictability and enabling higher transaction rate limits.
///
///         Deployed behind a plain 45-byte ERC-1167 proxy, so its behaviour is fully fixed by its (hardcoded)
///         implementation address.
contract DefaultHighRateAccount is DefaultAccount {
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
