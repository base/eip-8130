// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {AlwaysValidSandbox} from "../../../../src/verifiers/sandbox/AlwaysValidVerifier.sol";

contract AlwaysValidSandboxTest is Test {
    address sandbox;

    function setUp() public {
        sandbox = AlwaysValidSandbox.deploy(bytes32("test"));
    }

    function test_bytecodeIs8Bytes() public pure {
        assertEq(AlwaysValidSandbox.bytecode().length, 8);
    }

    function test_deployedCodeIs8Bytes() public view {
        assertEq(sandbox.code.length, 8);
    }

    function test_returnsTrue() public {
        (bool ok, bytes memory ret) =
            sandbox.staticcall(abi.encode(address(0x1), bytes32(uint256(1)), keccak256("test"), bytes("")));
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
                "verify(address,bytes32,bytes32,bytes)", address(0xdead), bytes32(0), keccak256("msg"), bytes("")
            )
        );
        assertTrue(ok);
        assertEq(abi.decode(ret, (uint256)), 1);
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
                    || op == 0xF3, // RETURN
                "unexpected opcode in verification code"
            );
        }
    }
}
