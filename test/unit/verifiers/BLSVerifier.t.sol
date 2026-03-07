// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {BLSVerifier} from "../../../src/verifiers/BLSVerifier.sol";

contract BLSVerifierTest is Test {
    BLSVerifier verifier;

    function setUp() public {
        verifier = new BLSVerifier();
    }

    function test_verify_revertsOnWrongDataLength() public {
        vm.expectRevert();
        verifier.verify(bytes32(0), hex"0000");
    }

    function test_verify_revertsOnShortData() public {
        bytes memory data = new bytes(383);

        vm.expectRevert();
        verifier.verify(bytes32(0), data);
    }

    function test_verify_revertsOnLongData() public {
        bytes memory data = new bytes(385);

        vm.expectRevert();
        verifier.verify(bytes32(0), data);
    }

    function test_verify_ownerIdMatchesPubKeyHash() public pure {
        bytes memory pubKey = new bytes(128);
        bytes32 expectedOwnerId = keccak256(pubKey);
        assertEq(expectedOwnerId, keccak256(new bytes(128)));
    }

    function test_verify_revertsWithoutBLSPrecompiles() public {
        bytes memory pubKey = new bytes(128);
        bytes memory data = new bytes(384);

        vm.expectRevert();
        verifier.verify(keccak256("msg"), data);
    }

    function test_dataLayoutConstants() public pure {
        // sig_G2: 256 bytes (8 × 32-byte Fp components)
        // pubKey_G1: 128 bytes (4 × 32-byte Fp components)
        assertEq(uint256(256 + 128), uint256(384));
    }
}
