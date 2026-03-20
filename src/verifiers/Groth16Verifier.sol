// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IVerifier} from "./IVerifier.sol";

/// @notice Groth16 ZK-SNARK verifier over BN254 using EIP-196/197 precompiles.
///
///         Enables any signature algorithm to be verified via a zero-knowledge
///         proof — e.g. Ed25519 verification wrapped in a Groth16 circuit.
///
///         The transaction hash is automatically bound as the first public input.
///         Additional public inputs (e.g. the foreign public key) and the full
///         verification key (VK) are passed in data and committed via ownerId.
///
///         ownerId = keccak256(vk || extraInputs)
///
///         data layout (k = numExtraInputs):
///           proof_A  (G1, 64)  || proof_B (G2, 128) || proof_C (G1, 64) = 256
///           || numExtraInputs (1)
///           || extraInputs (k × 32)
///           || vk_alpha (G1, 64) || vk_beta (G2, 128)
///           || vk_gamma (G2, 128) || vk_delta (G2, 128)
///           || vk_IC ((k + 2) × G1, (k + 2) × 64)
///
///         Public inputs for the circuit: [hash, extraInputs[0], …, extraInputs[k-1]]
///
///         Uses ecAdd (0x06), ecMul (0x07), ecPairing (0x08).
///
///         NOTE: For production use, deploy per-circuit verifiers with hardcoded
///         VKs to avoid the calldata overhead of passing the VK every transaction.
contract Groth16Verifier is IVerifier {
    uint256 private constant BN254_FP = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

    function verify(bytes32 hash, bytes calldata data) external view returns (bytes32 ownerId) {
        uint256 k = uint256(uint8(data[256]));
        uint256 vkOff = 257 + k * 32;
        uint256 icOff = vkOff + 448;
        require(data.length == icOff + (k + 2) * 64);

        ownerId = keccak256(abi.encodePacked(data[vkOff:], data[257:vkOff]));

        // ── Compute vk_x = IC[0] + hash·IC[1] + Σ(extraInputs[i]·IC[i+2]) ──

        (uint256 vkxX, uint256 vkxY) =
            (uint256(bytes32(data[icOff:icOff + 32])), uint256(bytes32(data[icOff + 32:icOff + 64])));

        {
            (uint256 mx, uint256 my) = _ecMul(
                uint256(bytes32(data[icOff + 64:icOff + 96])),
                uint256(bytes32(data[icOff + 96:icOff + 128])),
                uint256(hash)
            );
            (vkxX, vkxY) = _ecAdd(vkxX, vkxY, mx, my);
        }

        for (uint256 i; i < k; i++) {
            uint256 inputVal = uint256(bytes32(data[257 + i * 32:289 + i * 32]));
            uint256 ic = icOff + (i + 2) * 64;
            (uint256 mx, uint256 my) =
                _ecMul(uint256(bytes32(data[ic:ic + 32])), uint256(bytes32(data[ic + 32:ic + 64])), inputVal);
            (vkxX, vkxY) = _ecAdd(vkxX, vkxY, mx, my);
        }

        // ── Pairing check: e(−A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) == 1 ──

        uint256[24] memory buf;

        // Pair 1: −A, B
        buf[0] = uint256(bytes32(data[0:32]));
        uint256 ay = uint256(bytes32(data[32:64]));
        buf[1] = ay == 0 ? 0 : BN254_FP - ay;
        buf[2] = uint256(bytes32(data[64:96]));
        buf[3] = uint256(bytes32(data[96:128]));
        buf[4] = uint256(bytes32(data[128:160]));
        buf[5] = uint256(bytes32(data[160:192]));

        // Pair 2: α, β
        buf[6] = uint256(bytes32(data[vkOff:vkOff + 32]));
        buf[7] = uint256(bytes32(data[vkOff + 32:vkOff + 64]));
        buf[8] = uint256(bytes32(data[vkOff + 64:vkOff + 96]));
        buf[9] = uint256(bytes32(data[vkOff + 96:vkOff + 128]));
        buf[10] = uint256(bytes32(data[vkOff + 128:vkOff + 160]));
        buf[11] = uint256(bytes32(data[vkOff + 160:vkOff + 192]));

        // Pair 3: vk_x, γ
        buf[12] = vkxX;
        buf[13] = vkxY;
        buf[14] = uint256(bytes32(data[vkOff + 192:vkOff + 224]));
        buf[15] = uint256(bytes32(data[vkOff + 224:vkOff + 256]));
        buf[16] = uint256(bytes32(data[vkOff + 256:vkOff + 288]));
        buf[17] = uint256(bytes32(data[vkOff + 288:vkOff + 320]));

        // Pair 4: C, δ
        buf[18] = uint256(bytes32(data[192:224]));
        buf[19] = uint256(bytes32(data[224:256]));
        buf[20] = uint256(bytes32(data[vkOff + 320:vkOff + 352]));
        buf[21] = uint256(bytes32(data[vkOff + 352:vkOff + 384]));
        buf[22] = uint256(bytes32(data[vkOff + 384:vkOff + 416]));
        buf[23] = uint256(bytes32(data[vkOff + 416:vkOff + 448]));

        uint256[1] memory result;
        bool ok;
        assembly {
            ok := staticcall(gas(), 0x08, buf, 768, result, 32)
        }
        if (!ok || result[0] != 1) return bytes32(0);
    }

    function _ecAdd(uint256 x1, uint256 y1, uint256 x2, uint256 y2) private view returns (uint256, uint256) {
        uint256[4] memory input = [x1, y1, x2, y2];
        uint256[2] memory output;
        assembly {
            if iszero(staticcall(gas(), 0x06, input, 128, output, 64)) { revert(0, 0) }
        }
        return (output[0], output[1]);
    }

    function _ecMul(uint256 px, uint256 py, uint256 s) private view returns (uint256, uint256) {
        uint256[3] memory input = [px, py, s];
        uint256[2] memory output;
        assembly {
            if iszero(staticcall(gas(), 0x07, input, 96, output, 64)) { revert(0, 0) }
        }
        return (output[0], output[1]);
    }
}
