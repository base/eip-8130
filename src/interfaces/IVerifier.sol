// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Verifier interface for EIP-8130 signature verification.
///         Verifiers derive the ownerId from the provided signature data and return it.
///         Returns bytes32(0) for invalid signatures.
interface IVerifier {
    /// @param hash The hash to verify the signature for
    /// @param data Verifier-specific signature data (includes public key material)
    /// @return ownerId The authenticated owner identifier, or bytes32(0) if invalid
    function verify(bytes32 hash, bytes calldata data) external view returns (bytes32 ownerId);
}
