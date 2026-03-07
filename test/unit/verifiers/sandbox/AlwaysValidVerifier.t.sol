// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {AlwaysValidSandbox} from "../../../../src/verifiers/sandbox/AlwaysValidVerifier.sol";

contract AlwaysValidSandboxTest is Test {
    address sandbox;

    function setUp() public {
        sandbox = AlwaysValidSandbox.deploy(bytes32("test"));
    }

    function test_deployedCodeMatchesBytecode() public view {
        assertEq(sandbox.code.length, AlwaysValidSandbox.bytecode().length);
    }

    function test_returnsOwnerIdFromData() public {
        bytes32 ownerId = bytes32(uint256(0xBEEF));
        (bool ok, bytes memory ret) =
            sandbox.staticcall(abi.encodeWithSignature("verify(bytes32,bytes)", keccak256("test"), abi.encode(ownerId)));
        assertTrue(ok);
        assertEq(abi.decode(ret, (bytes32)), ownerId);
    }

    function test_returnsOwnerIdViaVerifySelector() public {
        bytes32 ownerId = bytes32(uint256(0xDEAD));
        (bool ok, bytes memory ret) =
            sandbox.staticcall(abi.encodeWithSignature("verify(bytes32,bytes)", keccak256("msg"), abi.encode(ownerId)));
        assertTrue(ok);
        assertEq(abi.decode(ret, (bytes32)), ownerId);
    }

    function test_onlyAllowedOpcodes() public view {
        bytes memory code = sandbox.code;
        for (uint256 i = 0; i < code.length; i++) {
            uint8 op = uint8(code[i]);
            if (op >= 0x60 && op <= 0x7F) {
                i += (op - 0x5F);
                continue;
            }
            assertTrue(
                op == 0x5F // PUSH0
                    || op == 0x52 // MSTORE
                    || op == 0x35 // CALLDATALOAD
                    || op == 0x01 // ADD
                    || op == 0xF3, // RETURN
                "unexpected opcode in verification code"
            );
        }
    }
}
