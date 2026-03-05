// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {DefaultAccount} from "./DefaultAccount.sol";

/// @notice Locked-aware account variant. Extends DefaultAccount with ETH movement
///         restrictions when the account policy is locked.
///         Costs one extra external call + SLOAD per transaction for the lock check.
contract DefaultHighThroughputAccount is DefaultAccount {
    constructor(address accountConfiguration) DefaultAccount(accountConfiguration) {}

    function executeBatch(Call[] calldata calls) external override {
        require(msg.sender == address(this));

        (bool locked,,) = ACCOUNT_CONFIGURATION.getAccountPolicy(address(this));

        for (uint256 i; i < calls.length; i++) {
            if (locked) require(calls[i].value == 0);
            (bool success,) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            require(success);
        }
    }
}
