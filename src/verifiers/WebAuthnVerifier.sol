// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {WebAuthn} from "openzeppelin/utils/cryptography/WebAuthn.sol";

import {IVerifier} from "../interfaces/IVerifier.sol";

/// @notice P-256 WebAuthn/Passkey verifier. ownerId = keccak256(pub_key_x || pub_key_y).
contract WebAuthnVerifier is IVerifier {
    function verify(bytes32 hash, bytes calldata data) external view returns (bytes32 ownerId) {
        (WebAuthn.WebAuthnAuth memory auth, bytes32 x, bytes32 y) =
            abi.decode(data, (WebAuthn.WebAuthnAuth, bytes32, bytes32));
        ownerId = keccak256(abi.encodePacked(x, y));
        if (!WebAuthn.verify({challenge: abi.encode(hash), auth: auth, qx: x, qy: y, requireUV: false})) {
            return bytes32(0);
        }
    }
}
