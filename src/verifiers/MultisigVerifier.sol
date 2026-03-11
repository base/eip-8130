// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

import {IVerifier} from "./IVerifier.sol";

/// @notice K1 multisig verifier. Threshold M-of-N using secp256k1 ECDSA.
///
///         ownerId = keccak256(threshold (1) || signerCount (1)
///                           || signer_0 (20) || ... || signer_n (20))
///                 Signers MUST be sorted ascending by address.
///
///         data  = threshold (1) || signerCount (1) || signers (signerCount × 20)
///                 || sigs (sigCount × 65, each: r (32) || s (32) || v (1))
///                 Signatures MUST be ordered by ascending recovered address.
///
///         Only calls the ecrecover precompile (0x01) — sandbox-compatible.
contract MultisigVerifier is IVerifier {
    function verify(bytes32 hash, bytes calldata data) external pure returns (bytes32 ownerId) {
        require(data.length >= 2);
        uint256 threshold = uint256(uint8(data[0]));
        uint256 signerCount = uint256(uint8(data[1]));
        require(threshold > 0 && threshold <= signerCount);

        uint256 sigDataStart = 2 + signerCount * 20;
        require(data.length >= sigDataStart);
        require((data.length - sigDataStart) % 65 == 0);
        uint256 sigCount = (data.length - sigDataStart) / 65;
        require(sigCount >= threshold);

        ownerId = keccak256(data[:sigDataStart]);

        for (uint256 j = 1; j < signerCount; j++) {
            require(_signerAt(data, j) > _signerAt(data, j - 1));
        }

        uint256 signerIdx;
        address prev;

        for (uint256 i; i < sigCount; i++) {
            uint256 off = sigDataStart + i * 65;
            address recovered = ECDSA.recover(
                hash, uint8(data[off + 64]), bytes32(data[off:off + 32]), bytes32(data[off + 32:off + 64])
            );
            require(recovered > prev);
            prev = recovered;

            bool found;
            while (signerIdx < signerCount) {
                address signer = _signerAt(data, signerIdx);
                signerIdx++;
                if (signer == recovered) {
                    found = true;
                    break;
                }
                if (signer > recovered) return bytes32(0);
            }
            if (!found) return bytes32(0);
        }
    }

    function _signerAt(bytes calldata data, uint256 idx) private pure returns (address signer) {
        uint256 off = 2 + idx * 20;
        assembly {
            signer := shr(96, calldataload(add(data.offset, off)))
        }
    }
}
