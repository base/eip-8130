// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {WebAuthn} from "openzeppelin/utils/cryptography/WebAuthn.sol";

import {IAuthenticator} from "../interfaces/IAuthenticator.sol";

/// @notice P-256 WebAuthn/Passkey authenticator; actorId = keccak256(pub_key_x || pub_key_y).
///
/// @dev Whether an assertion must carry the User-Verified (UV) flag is fixed per deployment via {REQUIRE_UV}, not
///      chosen by the signer: two canonical instances are deployed (UV-optional and UV-required) and an account
///      picks the guarantee it wants by which authenticator address it registers the key under. The actorId
///      derivation is identical for both, so the same passkey can be registered under either (or both) without a
///      different identity.
///
/// @author Coinbase
contract WebAuthnAuthenticator is IAuthenticator {
    /// @notice When true, assertions without the User-Verified (UV) flag in authenticatorData do not authenticate.
    ///         User-Present (UP) is always required by WebAuthn.verify regardless.
    bool public immutable REQUIRE_UV;

    /// @param requireUV Whether this instance requires the UV flag on every assertion.
    constructor(bool requireUV) {
        REQUIRE_UV = requireUV;
    }

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
        if (!WebAuthn.verify({challenge: abi.encode(hash), auth: auth, qx: x, qy: y, requireUV: REQUIRE_UV})) {
            return bytes32(0);
        }
    }
}
