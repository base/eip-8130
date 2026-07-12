// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Authenticator interface for EIP-8130 signature authentication. Implementations derive the actorId
///         from the provided signature data and return it, or bytes32(0) for an invalid signature.
/// @author Coinbase
interface IAuthenticator {
    /// @notice Authenticates a signature and returns the signer's actorId, or bytes32(0) if invalid.
    ///
    /// @param hash The hash to authenticate the signature for.
    /// @param data Authenticator-specific signature data (includes public key material).
    ///
    /// @return actorId The authenticated actor identifier, or bytes32(0) if invalid.
    function authenticate(bytes32 hash, bytes calldata data) external view returns (bytes32 actorId);
}
