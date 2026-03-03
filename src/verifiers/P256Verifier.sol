// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {P256} from "openzeppelin/utils/cryptography/P256.sol";

import {IVerifier} from "./IVerifier.sol";

contract P256Verifier is IVerifier {
    function verifyIntent(address account, bytes32 ownerId, bytes32 hash, bytes calldata data)
        external
        view
        returns (bool)
    {
        (bytes32 r, bytes32 s, bytes32 x, bytes32 y) = abi.decode(data, (bytes32, bytes32, bytes32, bytes32));
        require(keccak256(abi.encode(x, y)) == ownerId);
        return P256.verify({h: hash, r: r, s: s, qx: x, qy: y});
    }
}
