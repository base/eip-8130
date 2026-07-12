// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../AccountConfiguration.sol";
import {IAuthenticator} from "../interfaces/IAuthenticator.sol";

/// @notice Delegates authentication to another account's actor configuration; a single hop only.
///         actorId = bytes32(bytes20(delegate_address))
///
///         This contract exists for non-8130 chains where verifySignature() runs in normal EVM.
///         On 8130 chains, the protocol handles DELEGATE directly at the protocol level.
///
///         Data layout: delegate_address (20) || nested_authenticator (20) || nested_data
///
/// @author Coinbase
contract DelegateAuthenticator is IAuthenticator {
    /// @notice The AccountConfiguration system contract used to validate the nested (delegate) signature.
    AccountConfiguration public immutable ACCOUNT_CONFIGURATION;

    /// @notice Deploys the authenticator bound to an AccountConfiguration instance.
    /// @param accountConfiguration Address of the AccountConfiguration system contract.
    constructor(address accountConfiguration) {
        ACCOUNT_CONFIGURATION = AccountConfiguration(accountConfiguration);
    }

    /// @notice Authenticates by delegating to another account's actor configuration; only one hop is permitted.
    ///
    /// @dev Reverts when `data` is shorter than 40 bytes.
    /// @dev Reverts when the nested authenticator is this contract (recursive delegation is not permitted).
    /// @dev Reverts when the delegate account does not validate the nested signature.
    ///
    /// @param hash The digest being authenticated.
    /// @param data delegate address (20) then the nested auth blob (nested authenticator address then its data).
    ///
    /// @return actorId The delegate's actorId, bytes32(bytes20(delegate)), when the nested signature is valid.
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
