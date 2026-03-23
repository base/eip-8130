// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

import {IVerifier} from "../interfaces/IVerifier.sol";

/// @notice secp256k1 ECDSA verifier. ownerId = bytes32(bytes20(ecrecover(hash, v, r, s))).
contract K1Verifier is IVerifier {
    function verify(bytes32 hash, bytes calldata data) external pure returns (bytes32 ownerId) {
        address recovered = ECDSA.recover(hash, data);
        ownerId = bytes32(bytes20(recovered));
    }
}
