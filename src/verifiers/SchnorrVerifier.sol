// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IAuthVerifier} from "./IAuthVerifier.sol";

/// @notice Schnorr signature verifier over secp256k1 using the ecrecover precompile.
///
///         keyId  = keccak256(parity (1) || px (32))  — 33-byte compressed public key
///         data   = s (32) || e (32) || px (32) || parity (1)  — 97 bytes total
///
///         Signature scheme:
///           1. Pick random k, compute R = k·G
///           2. e = keccak256(address(R) || hash)
///           3. s = k + e·x  (mod N)  where x is the private key
///
///         Verification uses the ecrecover trick to recover address(s·G − e·P)
///         and checks e == keccak256(address(R) || hash).
///
///         Only calls the ecrecover precompile (0x01) — sandbox-compatible.
contract SchnorrVerifier is IAuthVerifier {
    uint256 private constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function verify(address, bytes32 keyId, bytes32 hash, bytes calldata data) external pure returns (bool) {
        require(data.length == 97);

        uint256 sVal = uint256(bytes32(data[0:32]));
        bytes32 e = bytes32(data[32:64]);
        uint256 pxVal = uint256(bytes32(data[64:96]));
        uint8 parity = uint8(data[96]);

        require(parity <= 1);
        require(keccak256(abi.encodePacked(parity, bytes32(pxVal))) == keyId);

        // ecrecover(h, v, r, s_ec) recovers Q = r⁻¹·(s_ec·R_pt − h·G).
        // Setting R_pt = P (the pubkey) via r = px, v = 27 + parity:
        //   Q = px⁻¹·(s_ec·P − h·G)
        // To get Q = s·G − e·P (Schnorr verification point R):
        //   h    = −s·px  (mod N)
        //   s_ec = −e·px  (mod N)
        bytes32 hEc = bytes32(N - mulmod(sVal, pxVal, N));
        bytes32 sEc = bytes32(N - mulmod(uint256(e), pxVal, N));

        address rAddr = ecrecover(hEc, 27 + parity, bytes32(pxVal), sEc);
        if (rAddr == address(0)) return false;

        return e == keccak256(abi.encodePacked(rAddr, hash));
    }
}
