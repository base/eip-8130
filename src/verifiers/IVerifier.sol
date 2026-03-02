// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVerifier {
    function verify(address account, bytes32 ownerId, bytes32 hash, bytes calldata signature)
        external
        pure
        returns (bool);
}
