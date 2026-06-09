// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

import {IAuthenticator} from "../interfaces/IAuthenticator.sol";

/// @notice secp256k1 ECDSA authenticator. actorId = bytes32(bytes20(ecrecover(hash, v, r, s))).
contract K1Authenticator is IAuthenticator {
    function authenticate(bytes32 hash, bytes calldata data) external pure returns (bytes32 actorId) {
        address recovered = ECDSA.recover(hash, data);
        actorId = bytes32(bytes20(recovered));
    }
}
