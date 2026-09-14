// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {WebAuthn} from "openzeppelin/utils/cryptography/WebAuthn.sol";

import {IAuthenticator} from "../interfaces/IAuthenticator.sol";

/// @notice P-256 WebAuthn/Passkey authenticator; actorId = keccak256(pub_key_x || pub_key_y).
/// @author Coinbase
contract WebAuthnAuthenticator is IAuthenticator {
    /// @notice Verifies a WebAuthn (P-256 passkey) assertion and returns the signer's actorId.
    ///
    /// @dev Reverts when `data` cannot be abi-decoded into (WebAuthn.WebAuthnAuth, bytes32, bytes32).
    ///
    /// @param hash The challenge digest; checked against the assertion's clientDataJSON.
    /// @param data abi.encode(WebAuthn.WebAuthnAuth assertion, bytes32 pub_key_x, bytes32 pub_key_y).
    ///
    /// @return actorId keccak256(pub_key_x || pub_key_y) if the assertion is valid, otherwise bytes32(0).
    function authenticate(bytes32 hash, bytes calldata data) external view returns (bytes32 actorId) {
        (WebAuthn.WebAuthnAuth memory auth, bytes32 x, bytes32 y) =
            abi.decode(data, (WebAuthn.WebAuthnAuth, bytes32, bytes32));
        actorId = keccak256(abi.encodePacked(x, y));
        if (!WebAuthn.verify({challenge: abi.encode(hash), auth: auth, qx: x, qy: y, requireUV: false})) {
            return bytes32(0);
        }
    }
}
