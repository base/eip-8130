// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {MultisigVerifier} from "../../../src/verifiers/MultisigVerifier.sol";

contract MultisigVerifierTest is Test {
    MultisigVerifier verifier;

    uint256 constant PK_A = 0xA01;
    uint256 constant PK_B = 0xB02;
    uint256 constant PK_C = 0xC03;

    function setUp() public {
        verifier = new MultisigVerifier();
    }

    // ── Helpers ──

    function _sortedSigners(uint256 pkA, uint256 pkB, uint256 pkC)
        internal
        pure
        returns (address[3] memory sorted, uint256[3] memory sortedPks)
    {
        address a = vm.addr(pkA);
        address b = vm.addr(pkB);
        address c = vm.addr(pkC);

        sorted = [a, b, c];
        sortedPks = [pkA, pkB, pkC];

        for (uint256 i = 0; i < 3; i++) {
            for (uint256 j = i + 1; j < 3; j++) {
                if (sorted[j] < sorted[i]) {
                    (sorted[i], sorted[j]) = (sorted[j], sorted[i]);
                    (sortedPks[i], sortedPks[j]) = (sortedPks[j], sortedPks[i]);
                }
            }
        }
    }

    function _buildKeyMaterial(uint8 threshold, address[3] memory signers) internal pure returns (bytes memory) {
        return abi.encodePacked(threshold, uint8(3), signers[0], signers[1], signers[2]);
    }

    function _buildData(bytes memory keyMaterial, uint256[] memory pks, bytes32 hash)
        internal
        pure
        returns (bytes memory)
    {
        address[] memory recovered = new address[](pks.length);
        bytes[] memory sigs = new bytes[](pks.length);

        for (uint256 i; i < pks.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[i], hash);
            recovered[i] = vm.addr(pks[i]);
            sigs[i] = abi.encodePacked(r, s, v);
        }

        for (uint256 i; i < recovered.length; i++) {
            for (uint256 j = i + 1; j < recovered.length; j++) {
                if (recovered[j] < recovered[i]) {
                    (recovered[i], recovered[j]) = (recovered[j], recovered[i]);
                    (sigs[i], sigs[j]) = (sigs[j], sigs[i]);
                }
            }
        }

        bytes memory allSigs;
        for (uint256 i; i < sigs.length; i++) {
            allSigs = abi.encodePacked(allSigs, sigs[i]);
        }

        return abi.encodePacked(keyMaterial, allSigs);
    }

    // ── 2-of-3 Tests ──

    function test_2of3_validWithSignersAB() public view {
        (address[3] memory signers, uint256[3] memory pks) = _sortedSigners(PK_A, PK_B, PK_C);
        bytes memory keyMaterial = _buildKeyMaterial(2, signers);
        bytes32 expectedOwnerId = keccak256(keyMaterial);
        bytes32 hash = keccak256("2of3 test");

        uint256[] memory signingPks = new uint256[](2);
        signingPks[0] = pks[0];
        signingPks[1] = pks[1];

        bytes memory data = _buildData(keyMaterial, signingPks, hash);
        bytes32 ownerId = verifier.verify(hash, data);
        assertEq(ownerId, expectedOwnerId);
    }

    function test_2of3_validWithSignersAC() public view {
        (address[3] memory signers, uint256[3] memory pks) = _sortedSigners(PK_A, PK_B, PK_C);
        bytes memory keyMaterial = _buildKeyMaterial(2, signers);
        bytes32 expectedOwnerId = keccak256(keyMaterial);
        bytes32 hash = keccak256("2of3 AC");

        uint256[] memory signingPks = new uint256[](2);
        signingPks[0] = pks[0];
        signingPks[1] = pks[2];

        bytes memory data = _buildData(keyMaterial, signingPks, hash);
        assertEq(verifier.verify(hash, data), expectedOwnerId);
    }

    function test_2of3_validWithSignersBC() public view {
        (address[3] memory signers, uint256[3] memory pks) = _sortedSigners(PK_A, PK_B, PK_C);
        bytes memory keyMaterial = _buildKeyMaterial(2, signers);
        bytes32 expectedOwnerId = keccak256(keyMaterial);
        bytes32 hash = keccak256("2of3 BC");

        uint256[] memory signingPks = new uint256[](2);
        signingPks[0] = pks[1];
        signingPks[1] = pks[2];

        bytes memory data = _buildData(keyMaterial, signingPks, hash);
        assertEq(verifier.verify(hash, data), expectedOwnerId);
    }

    function test_2of3_validWithAll3Signatures() public view {
        (address[3] memory signers, uint256[3] memory pks) = _sortedSigners(PK_A, PK_B, PK_C);
        bytes memory keyMaterial = _buildKeyMaterial(2, signers);
        bytes32 expectedOwnerId = keccak256(keyMaterial);
        bytes32 hash = keccak256("2of3 all");

        uint256[] memory signingPks = new uint256[](3);
        signingPks[0] = pks[0];
        signingPks[1] = pks[1];
        signingPks[2] = pks[2];

        bytes memory data = _buildData(keyMaterial, signingPks, hash);
        assertEq(verifier.verify(hash, data), expectedOwnerId);
    }

    function test_2of3_failsWithOnly1Signature() public {
        (address[3] memory signers, uint256[3] memory pks) = _sortedSigners(PK_A, PK_B, PK_C);
        bytes memory keyMaterial = _buildKeyMaterial(2, signers);
        bytes32 hash = keccak256("2of3 insufficient");

        uint256[] memory signingPks = new uint256[](1);
        signingPks[0] = pks[0];

        bytes memory data = _buildData(keyMaterial, signingPks, hash);

        vm.expectRevert();
        verifier.verify(hash, data);
    }

    function test_2of3_failsWithWrongHash() public view {
        (address[3] memory signers, uint256[3] memory pks) = _sortedSigners(PK_A, PK_B, PK_C);
        bytes memory keyMaterial = _buildKeyMaterial(2, signers);
        bytes32 hash = keccak256("correct");
        bytes32 wrongHash = keccak256("wrong");

        uint256[] memory signingPks = new uint256[](2);
        signingPks[0] = pks[0];
        signingPks[1] = pks[1];

        bytes memory data = _buildData(keyMaterial, signingPks, hash);
        bytes32 ownerId = verifier.verify(wrongHash, data);
        assertEq(ownerId, bytes32(0));
    }

    function test_2of3_failsWithNonMemberSignature() public view {
        (address[3] memory signers, uint256[3] memory pks) = _sortedSigners(PK_A, PK_B, PK_C);
        bytes memory keyMaterial = _buildKeyMaterial(2, signers);
        bytes32 hash = keccak256("2of3 outsider");

        uint256 outsiderPk = 0xDEAD;
        uint256[] memory signingPks = new uint256[](2);
        signingPks[0] = pks[0];
        signingPks[1] = outsiderPk;

        bytes memory data = _buildData(keyMaterial, signingPks, hash);
        bytes32 ownerId = verifier.verify(hash, data);
        assertEq(ownerId, bytes32(0));
    }
}
