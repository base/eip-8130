// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {AlwaysValidSandbox} from "../../../src/sandbox/AlwaysValidVerifier.sol";

contract AlwaysValidSandboxTest is Test {
    address sandbox;

    function setUp() public {
        sandbox = AlwaysValidSandbox.deploy(bytes32("test"));
    }

    function test_bytecodeIs15Bytes() public pure {
        assertEq(AlwaysValidSandbox.bytecode().length, 15);
    }

    function test_deployedCodeIs15Bytes() public view {
        assertEq(sandbox.code.length, 15);
    }

    function test_has8130Header() public view {
        bytes memory code = sandbox.code;
        assertEq(uint8(code[0]), 0x60); // PUSH1
        assertEq(uint8(code[1]), 0x06); // jump offset
        assertEq(uint8(code[2]), 0x56); // JUMP
        assertEq(uint8(code[3]), 0x81); // magic hi
        assertEq(uint8(code[4]), 0x30); // magic lo
        assertEq(uint8(code[5]), 0x00); // version 0
        assertEq(uint8(code[6]), 0x5B); // JUMPDEST
    }

    function test_returnsTrue() public {
        (bool ok, bytes memory ret) = sandbox.staticcall(
            abi.encode(address(0x1), bytes32(uint256(1)), keccak256("test"), bytes(""))
        );
        assertTrue(ok);
        assertEq(abi.decode(ret, (uint256)), 1);
    }

    function test_returnsTrueForAnyInput() public {
        (bool ok, bytes memory ret) = sandbox.staticcall(hex"");
        assertTrue(ok);
        assertEq(abi.decode(ret, (uint256)), 1);
    }

    function test_returnsTrueViaVerifySelector() public {
        (bool ok, bytes memory ret) = sandbox.staticcall(
            abi.encodeWithSignature(
                "verify(address,bytes32,bytes32,bytes)",
                address(0xdead),
                bytes32(0),
                keccak256("msg"),
                bytes("")
            )
        );
        assertTrue(ok);
        assertEq(abi.decode(ret, (uint256)), 1);
    }

    function test_onlyAllowedOpcodes() public view {
        bytes memory code = sandbox.code;
        // After header (7 bytes), the verification code should only contain allowed opcodes
        for (uint256 i = 7; i < code.length; i++) {
            uint8 op = uint8(code[i]);
            // Skip immediate bytes for PUSH instructions
            if (op >= 0x60 && op <= 0x7F) {
                i += (op - 0x5F); // skip immediate bytes
                continue;
            }
            assertTrue(
                op == 0x5F // PUSH0
                    || op == 0x52 // MSTORE
                    || op == 0xF3, // RETURN
                "unexpected opcode in verification code"
            );
        }
    }
}
