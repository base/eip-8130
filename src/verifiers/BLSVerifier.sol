// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {BLS} from "solady/utils/ext/ithaca/BLS.sol";

import {IAuthVerifier} from "./IAuthVerifier.sol";

/// @notice BLS12-381 signature verifier using EIP-2537 precompiles.
///
///         ownerId = keccak256(pubKey_G1)  where pubKey_G1 is 128-byte uncompressed G1 point
///         data    = sig_G2 (256 bytes) || pubKey_G1 (128 bytes)  — 384 bytes total
///
///         Verification performs a pairing check:
///           e(-pubKey, H(hash)) · e(G1_gen, sig) == 1
///
///         Requires EIP-2537 BLS12-381 precompiles (Pectra+).
contract BLSVerifier is IAuthVerifier {
    // BLS12-381 base field modulus p (two halves, big-endian)
    bytes32 private constant P_A = 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7;
    bytes32 private constant P_B = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

    function verify(bytes32 hash, bytes calldata data) external view returns (bytes32 ownerId) {
        require(data.length == 384);
        ownerId = keccak256(data[256:384]);

        BLS.G2Point memory msgPoint = BLS.hashToG2(abi.encodePacked(hash));

        BLS.G1Point[] memory g1s = new BLS.G1Point[](2);
        BLS.G2Point[] memory g2s = new BLS.G2Point[](2);

        g1s[0] = _negateG1(data[256:384]);
        g1s[1] = _g1Generator();
        g2s[0] = msgPoint;
        g2s[1] = _decodeG2(data[0:256]);

        if (!BLS.pairing(g1s, g2s)) return bytes32(0);
    }

    function _decodeG2(bytes calldata sig) internal pure returns (BLS.G2Point memory) {
        return BLS.G2Point(
            bytes32(sig[0:32]),
            bytes32(sig[32:64]),
            bytes32(sig[64:96]),
            bytes32(sig[96:128]),
            bytes32(sig[128:160]),
            bytes32(sig[160:192]),
            bytes32(sig[192:224]),
            bytes32(sig[224:256])
        );
    }

    /// @dev Negate a G1 point by negating the y-coordinate in Fp: y_neg = p - y.
    function _negateG1(bytes calldata pk) internal pure returns (BLS.G1Point memory point) {
        point.x_a = bytes32(pk[0:32]);
        point.x_b = bytes32(pk[32:64]);

        uint256 y_a = uint256(bytes32(pk[64:96]));
        uint256 y_b = uint256(bytes32(pk[96:128]));

        unchecked {
            uint256 borrow = uint256(P_B) < y_b ? 1 : 0;
            point.y_b = bytes32(uint256(P_B) - y_b);
            point.y_a = bytes32(uint256(P_A) - y_a - borrow);
        }
    }

    function _g1Generator() internal pure returns (BLS.G1Point memory) {
        return BLS.G1Point(
            bytes32(0x0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f),
            bytes32(0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb),
            bytes32(0x0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4),
            bytes32(0xfcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1)
        );
    }
}
