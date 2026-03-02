// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVerifier {
    /// @notice Verify a signature for a given account, ownerId, hash, and data
    ///
    /// @param account The account to verify the signature for
    /// @param ownerId The ownerId to verify the signature for
    /// @param hash The hash to verify the signature for
    /// @param data The data to verify the signature for
    ///
    /// @return true if the signature is valid, false otherwise
    function verify(address account, bytes32 ownerId, bytes32 hash, bytes calldata data) external pure returns (bool);
}
