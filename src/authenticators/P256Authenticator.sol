// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {P256} from "openzeppelin/utils/cryptography/P256.sol";

import {IAuthenticator} from "../interfaces/IAuthenticator.sol";

/// @notice P-256 raw ECDSA authenticator; actorId = keccak256(pub_key_x || pub_key_y).
///
/// @dev Data layout: r (32) || s (32) || pub_key_x (32) || pub_key_y (32) || pre_hash (1). The trailing
///      pre_hash byte is accepted for native-authenticator layout consistency and is not otherwise interpreted.
///
/// @author Coinbase
contract P256Authenticator is IAuthenticator {
    /// @notice Verifies a raw secp256r1 (P-256) signature and returns the signer's actorId.
    ///
    /// @dev Reverts when `data` is not exactly 129 bytes.
    ///
    /// @param hash The digest that was signed.
    /// @param data r (32) || s (32) || pub_key_x (32) || pub_key_y (32) || pre_hash (1).
    ///
    /// @return actorId keccak256(pub_key_x || pub_key_y) if the signature is valid, otherwise bytes32(0).
    function authenticate(bytes32 hash, bytes calldata data) external view returns (bytes32 actorId) {
        require(data.length == 129);
        bytes32 r = bytes32(data[:32]);
        bytes32 s = bytes32(data[32:64]);
        bytes32 x = bytes32(data[64:96]);
        bytes32 y = bytes32(data[96:128]);
        actorId = keccak256(abi.encodePacked(x, y));
        if (!P256.verify(hash, r, s, x, y)) return bytes32(0);
    }
}
