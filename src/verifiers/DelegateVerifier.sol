// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IVerifier} from "../interfaces/IVerifier.sol";
import {AccountConfiguration} from "../AccountConfiguration.sol";
import {IAccountConfiguration} from "../interfaces/IAccountConfiguration.sol";

/// @notice Delegates verification to another account's owner configuration.
///         ownerId = bytes32(bytes20(delegate_address)). Only 1 hop permitted.
///
///         This contract exists for non-8130 chains where verifySignature() runs
///         in normal EVM. On 8130 chains, the protocol handles DELEGATE directly
///         at the protocol level.
///
///         Data layout: delegate_address (20) || nested_verifier_type (1) || nested_data
contract DelegateVerifier is IVerifier {
    AccountConfiguration public immutable ACCOUNT_CONFIGURATION;

    constructor(address accountConfiguration) {
        ACCOUNT_CONFIGURATION = AccountConfiguration(accountConfiguration);
    }

    function verify(bytes32 hash, bytes calldata data) external view returns (bytes32 ownerId) {
        require(data.length >= 20);
        address delegate = address(bytes20(data[:20]));
        bytes calldata nestedData = data[20:];

        ownerId = bytes32(bytes20(delegate));

        IAccountConfiguration.Verification memory v = abi.decode(nestedData, (IAccountConfiguration.Verification));

        // Prevent recursive delegation (only 1 hop permitted)
        require(ACCOUNT_CONFIGURATION.getOwnerConfig(delegate, v.ownerId).verifier != address(this));

        ACCOUNT_CONFIGURATION.verify(delegate, hash, v);
    }
}
