// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Keystore} from "../Keystore.sol";
import {IAuthenticator} from "../interfaces/IAuthenticator.sol";
import {ActorId} from "../libraries/ActorId.sol";
import {Scopes} from "../libraries/Scopes.sol";

/// @notice Delegates authentication to another account's actor configuration; a single hop only.
///
///         The returned actorId encodes WHICH CLASS of the delegate account's actors signed, so the registering
///         account chooses the class it trusts simply by which actorId it authorizes:
///           - `ActorId.fromAddress(delegate)`            — the nested signer is an ADMIN (scope 0) of `delegate`.
///           - `ActorId.operatorOfAddress(delegate)`      — the nested signer is a non-admin OPERATOR of `delegate`
///                                                          ({Scopes.isOperator}; e.g. its hot key).
///         An account that wants both classes to act for it registers both actorIds. Any other nested scope
///         (POLICY-only, payer-only, ...) does not authenticate.
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

    /// @notice The nested signer is neither an admin nor an operator of the delegate account (or did not validate).
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
    /// @dev Reverts with InvalidNestedSignature when the delegate account does not validate the nested signature,
    ///      or validates it to an actor that is neither admin nor operator.
    /// @dev The class is decided by the nested signer's scope on `delegate`, not by anything the signer declares:
    ///      admin (scope 0) resolves to the admin-class actorId, an OPERATOR-bearing non-admin scope to the
    ///      operator-class actorId. Keystore's actorId binding then enforces the registering account's choice — a
    ///      class the account did not authorize resolves to an unregistered actorId and fails there.
    ///
    /// @param hash The digest being authenticated.
    /// @param data delegate address (20) then the nested auth blob (nested authenticator address then its data).
    ///
    /// @return actorId `ActorId.fromAddress(delegate)` for an admin nested signer, or
    ///         `ActorId.operatorOfAddress(delegate)` for an operator nested signer.
    function authenticate(bytes32 hash, bytes calldata data) external view returns (bytes32 actorId) {
        if (data.length < 40) revert InvalidDataLength();
        address delegate = address(bytes20(data[:20]));
        bytes calldata nestedAuth = data[20:];

        // Prevent recursive delegation (only 1 hop permitted)
        address nestedAuthenticator = address(bytes20(nestedAuth[:20]));
        if (nestedAuthenticator == address(this)) revert RecursiveDelegation();

        uint16 nestedScope;
        try KEYSTORE.authenticateActor(delegate, hash, nestedAuth) returns (bytes32, uint16 scope) {
            nestedScope = scope;
        } catch {
            revert InvalidNestedSignature();
        }

        if (nestedScope == 0) return ActorId.fromAddress(delegate);
        if (Scopes.isOperator(nestedScope)) return ActorId.operatorOfAddress(delegate);
        revert InvalidNestedSignature();
    }
}
