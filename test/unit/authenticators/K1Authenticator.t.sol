// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract K1AuthenticatorTest is AccountConfigurationTest {
    function test_authenticate_validSignature(uint256 pk) public view {
        pk = bound(pk, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        address signer = vm.addr(pk);
        bytes32 expectedActorId = bytes32(bytes20(signer));
        bytes32 hash = keccak256("test message");

        bytes memory sig = _signDigest(pk, hash);
        bytes32 actorId = k1Authenticator.authenticate(hash, sig);
        assertEq(actorId, expectedActorId);
    }

    function test_authenticate_wrongKey(uint256 pk) public view {
        pk = bound(pk, 2, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        address wrongSigner = vm.addr(1);
        bytes32 wrongActorId = bytes32(bytes20(wrongSigner));
        bytes32 hash = keccak256("test message");

        bytes memory sig = _signDigest(pk, hash);
        bytes32 actorId = k1Authenticator.authenticate(hash, sig);
        assertTrue(actorId != wrongActorId);
    }

    function test_authenticate_wrongHash(uint256 pk) public view {
        pk = bound(pk, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        address signer = vm.addr(pk);
        bytes32 expectedActorId = bytes32(bytes20(signer));
        bytes32 hash = keccak256("test message");
        bytes32 wrongHash = keccak256("wrong message");

        bytes memory sig = _signDigest(pk, hash);
        bytes32 actorId = k1Authenticator.authenticate(wrongHash, sig);
        assertTrue(actorId != expectedActorId);
    }

    function test_authenticate_deterministicForSameInputs() public view {
        uint256 pk = 42;
        address signer = vm.addr(pk);
        bytes32 expectedActorId = bytes32(bytes20(signer));
        bytes32 hash = keccak256("test message");

        bytes memory sig = _signDigest(pk, hash);
        bytes32 result1 = k1Authenticator.authenticate(hash, sig);
        bytes32 result2 = k1Authenticator.authenticate(hash, sig);

        assertEq(result1, result2);
        assertEq(result1, expectedActorId);
    }
}
