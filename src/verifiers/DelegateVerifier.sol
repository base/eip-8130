// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IVerifier} from "./IVerifier.sol";
import {AccountConfiguration} from "../AccountConfiguration.sol";

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
        require(data.length >= 21);
        address delegate = address(bytes20(data[:20]));
        bytes calldata nestedAuth = data[20:];

        ownerId = bytes32(bytes20(delegate));

        require(uint8(nestedAuth[0]) != 0x04);

        (bool valid,,) = ACCOUNT_CONFIGURATION.verifySignature(delegate, hash, nestedAuth);
        require(valid);
    }
}
