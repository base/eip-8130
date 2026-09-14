// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {P256} from "openzeppelin/utils/cryptography/P256.sol";

import {IAuthenticator} from "../interfaces/IAuthenticator.sol";

/// @notice P-256 raw ECDSA authenticator; actorId = keccak256(pub_key_x || pub_key_y).
///
/// @dev Data layout: r (32) || s (32) || pub_key_x (32) || pub_key_y (32) || pre_hash (1).
///
///      `pre_hash` selects the message the signature is verified against, so the blob has exactly one valid encoding
///      per signature (an uninterpreted byte would make 256 distinct blobs valid for one signature):
///        - {PRE_HASH_NONE} (0x00): verify against `hash` directly (the default for signers that accept a raw digest).
///        - {PRE_HASH_SHA256} (0x01): verify against `sha256(hash)`. For signers (HSMs, secure enclaves, WebCrypto)
///          that hash their input with SHA-256 before signing and cannot be handed a digest to sign as-is.
///      Any other value reverts.
///
/// @author Coinbase
contract P256Authenticator is IAuthenticator {
    /// @notice `pre_hash` value: the signature is over `hash` itself.
    uint8 public constant PRE_HASH_NONE = 0x00;

    /// @notice `pre_hash` value: the signature is over `sha256(hash)`.
    uint8 public constant PRE_HASH_SHA256 = 0x01;

    /// @notice The auth data length is not exactly 129 bytes.
    error InvalidDataLength();

    /// @notice The trailing `pre_hash` byte is not {PRE_HASH_NONE} or {PRE_HASH_SHA256}.
    error InvalidPreHash(uint8 preHash);

    /// @notice Verifies a raw secp256r1 (P-256) signature and returns the signer's actorId.
    ///
    /// @dev Reverts with InvalidDataLength when `data` is not exactly 129 bytes.
    /// @dev Reverts with InvalidPreHash when the trailing byte is not a recognized `pre_hash` selector.
    ///
    /// @param hash The digest that was signed (or, with {PRE_HASH_SHA256}, the pre-image the signer SHA-256 hashed).
    /// @param data r (32) || s (32) || pub_key_x (32) || pub_key_y (32) || pre_hash (1).
    ///
    /// @return actorId keccak256(pub_key_x || pub_key_y) if the signature is valid, otherwise bytes32(0).
    function authenticate(bytes32 hash, bytes calldata data) external view returns (bytes32 actorId) {
        if (data.length != 129) revert InvalidDataLength();
        bytes32 r = bytes32(data[:32]);
        bytes32 s = bytes32(data[32:64]);
        bytes32 x = bytes32(data[64:96]);
        bytes32 y = bytes32(data[96:128]);
        uint8 preHash = uint8(data[128]);

        bytes32 message;
        if (preHash == PRE_HASH_NONE) {
            message = hash;
        } else if (preHash == PRE_HASH_SHA256) {
            message = sha256(abi.encodePacked(hash));
        } else {
            revert InvalidPreHash(preHash);
        }

        actorId = keccak256(abi.encodePacked(x, y));
        if (!P256.verify(message, r, s, x, y)) return bytes32(0);
    }
}
