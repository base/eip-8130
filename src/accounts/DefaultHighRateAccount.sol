// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Call, DefaultAccount} from "./DefaultAccount.sol";

/// @notice High-rate account variant for EIP-8130.
///
///         Extends DefaultAccount with one additional constraint:
///         blocks outbound ETH value transfers when the account is locked.
///         Combined with lock, ETH balance only decreases through gas fees,
///         giving mempools maximum balance predictability and enabling higher
///         transaction rate limits.
contract DefaultHighRateAccount is DefaultAccount {
    constructor(address accountConfiguration) DefaultAccount(accountConfiguration) {}

    function executeBatch(Call[] calldata calls) external override {
        require(_isAuthorizedCaller(msg.sender));
        for (uint256 i; i < calls.length; i++) {
            if (calls[i].value > 0) {
                (bool locked,,,) = ACCOUNT_CONFIGURATION.getLockStatus(address(this));
                require(!locked);
            }
            (bool success,) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            require(success);
        }
    }
}
