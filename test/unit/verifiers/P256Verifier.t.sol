// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract P256VerifierTest is AccountConfigurationTest {
    uint256 constant P256_PK = 0xdead00000000000000000000000000000000000000000000000000000000beef;

    function _p256ActorId(uint256 pk) internal returns (bytes32 actorId, bytes32 pubX, bytes32 pubY) {
        (uint256 x, uint256 y) = vm.publicKeyP256(pk);
        pubX = bytes32(x);
        pubY = bytes32(y);
        actorId = keccak256(abi.encodePacked(pubX, pubY));
    }

    function _p256SignData(uint256 pk, bytes32 hash) internal returns (bytes memory) {
        (bytes32 pubX, bytes32 pubY) = (bytes32(0), bytes32(0));
        {
            (uint256 x, uint256 y) = vm.publicKeyP256(pk);
            pubX = bytes32(x);
            pubY = bytes32(y);
        }
        (bytes32 r, bytes32 s) = vm.signP256(pk, hash);
        return abi.encodePacked(r, s, pubX, pubY, uint8(0));
    }

    function test_verify_validSignature() public {
        (bytes32 expectedActorId,,) = _p256ActorId(P256_PK);
        bytes32 hash = keccak256("test p256 message");
        bytes memory data = _p256SignData(P256_PK, hash);

        bytes32 actorId = p256Verifier.verify(hash, data);
        assertEq(actorId, expectedActorId);
    }

    function test_verify_wrongHash() public {
        bytes32 hash = keccak256("test p256 message");
        bytes32 wrongHash = keccak256("wrong message");
        bytes memory data = _p256SignData(P256_PK, hash);

        bytes32 actorId = p256Verifier.verify(wrongHash, data);
        assertEq(actorId, bytes32(0));
    }

    function test_verify_revertsWithWrongDataLength() public {
        bytes32 hash = keccak256("test");

        vm.expectRevert();
        p256Verifier.verify(hash, hex"deadbeef");
    }

    function test_verify_exactlyRequires129Bytes() public {
        (bytes32 expectedActorId,,) = _p256ActorId(P256_PK);
        bytes32 hash = keccak256("test");
        bytes memory data = _p256SignData(P256_PK, hash);

        assertEq(data.length, 129);
        bytes32 actorId = p256Verifier.verify(hash, data);
        assertEq(actorId, expectedActorId);
    }

    function test_verify_differentPrivateKeys() public {
        uint256 pk2 = 0x1234000000000000000000000000000000000000000000000000000000005678;
        (bytes32 actorId1,,) = _p256ActorId(P256_PK);
        (bytes32 actorId2,,) = _p256ActorId(pk2);

        assertTrue(actorId1 != actorId2);

        bytes32 hash = keccak256("test");
        bytes memory data1 = _p256SignData(P256_PK, hash);
        bytes memory data2 = _p256SignData(pk2, hash);

        assertEq(p256Verifier.verify(hash, data1), actorId1);
        assertEq(p256Verifier.verify(hash, data2), actorId2);
    }
}
