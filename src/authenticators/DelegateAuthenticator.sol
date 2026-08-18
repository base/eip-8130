// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Keystore} from "../Keystore.sol";
import {IAuthenticator} from "../interfaces/IAuthenticator.sol";
import {ActorId} from "../libraries/ActorId.sol";
import {Scopes} from "../libraries/Scopes.sol";

/// @notice Delegates authentication to another account's actor configuration; a single hop only.
///         actorId = ActorId.fromAddress(delegate_address)
///
///         Data layout: delegate_address (20) || nested_authenticator (20) || nested_data
///
/// @author Coinbase
contract DelegateAuthenticator is IAuthenticator {
    /// @notice The Keystore system contract used to validate the nested (delegate) signature.
    Keystore public immutable KEYSTORE;

    /// @notice The auth data is shorter than the 40-byte delegate + nested-authenticator prefix.
    error InvalidDataLength();

    /// @notice The nested authenticator points back to this contract; only one delegation hop is permitted.
    error RecursiveDelegation();

    /// @notice The nested signer is not an operational actor of the delegate account, so it may not vouch.
    error InvalidNestedSignature();

    /// @notice Deploys the authenticator bound to an Keystore instance.
    /// @param keystore Address of the Keystore system contract.
    constructor(address keystore) {
        KEYSTORE = Keystore(keystore);
    }

    /// @notice Authenticates by delegating to another account's actor configuration; only one hop is permitted.
    ///
    /// @dev Reverts with InvalidDataLength when `data` is shorter than 40 bytes.
    /// @dev Reverts with RecursiveDelegation when the nested authenticator is this contract (recursive delegation
    ///      is not permitted).
    /// @dev Reverts with InvalidNestedSignature when the nested auth does not resolve to an operational actor
    ///      (per Scopes.isOperator) on the delegate account.
    ///
    /// @param hash The digest being authenticated.
    /// @param data delegate address (20) then the nested auth blob (nested authenticator address then its data).
    ///
    /// @return actorId The delegate's actorId, ActorId.fromAddress(delegate), when the nested signature is valid.
    function authenticate(bytes32 hash, bytes calldata data) external view returns (bytes32 actorId) {
        if (data.length < 40) revert InvalidDataLength();
        address delegate = address(bytes20(data[:20]));
        bytes calldata nestedAuth = data[20:];

        actorId = ActorId.fromAddress(delegate);

        // Prevent recursive delegation (only 1 hop permitted)
        address nestedAuthenticator = address(bytes20(nestedAuth[:20]));
        if (nestedAuthenticator == address(this)) revert RecursiveDelegation();

        // The nested actor MUST be an operational actor (admin or SENDER without POLICY) of the delegate account,
        // matching the authority that can drive execution and sign (ERC-1271) as the account.
        try KEYSTORE.authenticateActor(delegate, hash, nestedAuth) returns (bytes32, uint16 nestedScope) {
            if (!Scopes.isOperator(nestedScope)) revert InvalidNestedSignature();
        } catch {
            revert InvalidNestedSignature();
        }
    }
}
