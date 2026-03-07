// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract K1VerifierTest is AccountConfigurationTest {
    function test_verify_validSignature(uint256 pk) public view {
        pk = bound(pk, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        address signer = vm.addr(pk);
        bytes32 expectedOwnerId = bytes32(bytes20(signer));
        bytes32 hash = keccak256("test message");

        bytes memory sig = _signDigest(pk, hash);
        bytes32 ownerId = k1Verifier.verify(hash, sig);
        assertEq(ownerId, expectedOwnerId);
    }

    function test_verify_wrongKey(uint256 pk) public view {
        pk = bound(pk, 2, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        address wrongSigner = vm.addr(1);
        bytes32 wrongOwnerId = bytes32(bytes20(wrongSigner));
        bytes32 hash = keccak256("test message");

        bytes memory sig = _signDigest(pk, hash);
        bytes32 ownerId = k1Verifier.verify(hash, sig);
        assertTrue(ownerId != wrongOwnerId);
    }

    function test_verify_wrongHash(uint256 pk) public view {
        pk = bound(pk, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        address signer = vm.addr(pk);
        bytes32 expectedOwnerId = bytes32(bytes20(signer));
        bytes32 hash = keccak256("test message");
        bytes32 wrongHash = keccak256("wrong message");

        bytes memory sig = _signDigest(pk, hash);
        bytes32 ownerId = k1Verifier.verify(wrongHash, sig);
        assertTrue(ownerId != expectedOwnerId);
    }

    function test_verify_deterministicForSameInputs() public view {
        uint256 pk = 42;
        address signer = vm.addr(pk);
        bytes32 expectedOwnerId = bytes32(bytes20(signer));
        bytes32 hash = keccak256("test message");

        bytes memory sig = _signDigest(pk, hash);
        bytes32 result1 = k1Verifier.verify(hash, sig);
        bytes32 result2 = k1Verifier.verify(hash, sig);

        assertEq(result1, result2);
        assertEq(result1, expectedOwnerId);
    }
}
