// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {P256} from "openzeppelin/utils/cryptography/P256.sol";

import {IVerifier} from "../interfaces/IVerifier.sol";

/// @notice P-256 raw ECDSA verifier. ownerId = keccak256(pub_key_x || pub_key_y).
/// @dev Data layout: r (32) || s (32) || pub_key_x (32) || pub_key_y (32) || pre_hash (1)
///      pre_hash byte is included for protocol-level native verifier consistency.
contract P256Verifier is IVerifier {
    function verify(bytes32 hash, bytes calldata data) external view returns (bytes32 ownerId) {
        require(data.length == 129);
        bytes32 r = bytes32(data[:32]);
        bytes32 s = bytes32(data[32:64]);
        bytes32 x = bytes32(data[64:96]);
        bytes32 y = bytes32(data[96:128]);
        ownerId = keccak256(abi.encodePacked(x, y));
        if (!P256.verify(hash, r, s, x, y)) return bytes32(0);
    }
}
