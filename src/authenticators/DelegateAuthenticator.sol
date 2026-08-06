// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Keystore} from "../Keystore.sol";
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
    /// @notice The Keystore system contract used to validate the nested (delegate) signature.
    Keystore public immutable KEYSTORE;

    /// @notice The auth data is shorter than the 40-byte delegate + nested-authenticator prefix.
    error InvalidDataLength();

    /// @notice The nested authenticator points back to this contract; only one delegation hop is permitted.
    error RecursiveDelegation();

    /// @notice The nested signer is not authorized to sign for the delegate account.
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
    /// @dev Reverts with InvalidNestedSignature when the delegate account does not validate the nested signature.
    ///
    /// @param hash The digest being authenticated.
    /// @param data delegate address (20) then the nested auth blob (nested authenticator address then its data).
    ///
    /// @return actorId The delegate's actorId, bytes32(bytes20(delegate)), when the nested signature is valid.
    function authenticate(bytes32 hash, bytes calldata data) external view returns (bytes32 actorId) {
        if (data.length < 40) revert InvalidDataLength();
        address delegate = address(bytes20(data[:20]));
        bytes calldata nestedAuth = data[20:];

        actorId = bytes32(bytes20(delegate));

        // Prevent recursive delegation (only 1 hop permitted)
        address nestedAuthenticator = address(bytes20(nestedAuth[:20]));
        if (nestedAuthenticator == address(this)) revert RecursiveDelegation();

        // The nested actor MUST be the admin (scope == 0x00) of the delegate account. This is enforced
        // independently of verifySignature, which is now operational (signing is not admin-only, but a delegate
        // vouch requires admin to preserve non-escalation): an operational SENDER key can sign for its own account,
        // yet it must NOT be able to vouch as a delegate here. authenticateActor reverts on any auth failure and
        // otherwise returns the resolved scope, so we require scope == 0x00 explicitly.
        try KEYSTORE.authenticateActor(delegate, hash, nestedAuth) returns (bytes32, uint8 nestedScope, address) {
            if (nestedScope != 0) revert InvalidNestedSignature();
        } catch {
            revert InvalidNestedSignature();
        }
    }
}
