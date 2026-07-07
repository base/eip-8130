// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../AccountConfiguration.sol";
import {IAuthenticator} from "../interfaces/IAuthenticator.sol";

/// @notice Delegates authentication to another account's actor configuration.
///         actorId = bytes32(bytes20(delegate_address)). Only 1 hop permitted.
///
///         This contract exists for non-8130 chains where verifySignature() runs
///         in normal EVM. On 8130 chains, the protocol handles DELEGATE directly
///         at the protocol level.
///
///         Data layout: delegate_address (20) || nested_authenticator (20) || nested_data
contract DelegateAuthenticator is IAuthenticator {
    AccountConfiguration public immutable ACCOUNT_CONFIGURATION;

    constructor(address accountConfiguration) {
        ACCOUNT_CONFIGURATION = AccountConfiguration(accountConfiguration);
    }

    function authenticate(bytes32 hash, bytes calldata data) external view returns (bytes32 actorId) {
        require(data.length >= 40);
        address delegate = address(bytes20(data[:20]));
        bytes calldata nestedAuth = data[20:];

        actorId = bytes32(bytes20(delegate));

        // Prevent recursive delegation (only 1 hop permitted)
        address nestedAuthenticator = address(bytes20(nestedAuth[:20]));
        require(nestedAuthenticator != address(this));

        // Nested signer must have SIGNATURE scope on the delegate account.
        require(ACCOUNT_CONFIGURATION.verifySignature(delegate, hash, nestedAuth));
    }
}
