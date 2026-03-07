// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Receiver} from "solady/accounts/Receiver.sol";

import {AccountConfiguration} from "../AccountConfiguration.sol";

import {Call} from "./DefaultAccount.sol";

/// @notice High-rate account variant for EIP-8130.
///
///         Blocks outbound ETH value transfers when the account is locked.
///         Combined with lock, ETH balance only decreases through gas fees,
///         giving mempools maximum balance predictability and enabling higher
///         transaction rate limits.
contract DefaultHighRateAccount is Receiver {
    AccountConfiguration public immutable ACCOUNT_CONFIGURATION;

    constructor(address accountConfiguration) {
        ACCOUNT_CONFIGURATION = AccountConfiguration(accountConfiguration);
    }

    /// @notice Execute a batch of calls. Only callable via self-call.
    ///         Refuses outbound value transfers when account is locked.
    function executeBatch(Call[] calldata calls) external {
        require(msg.sender == address(this));

        for (uint256 i; i < calls.length; i++) {
            if (calls[i].value > 0) {
                (bool locked,,) = ACCOUNT_CONFIGURATION.getLockState(address(this));
                require(!locked);
            }
            (bool success,) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            require(success);
        }
    }

    /// @notice ERC-1271 signature validation. Used by AccountConfiguration for portable change authorization.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        (bool valid,,) = ACCOUNT_CONFIGURATION.verifySignature(address(this), hash, signature);
        if (!valid) return bytes4(0xFFFFFFFF);
        return bytes4(0x1626ba7e);
    }
}
