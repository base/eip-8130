// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice Hand-written EIP-8130 sandbox verifier that always returns true.
///
///         This is the sandbox-native equivalent of AlwaysValidVerifier.sol.
///         Instead of Solidity-compiled bytecode (287 bytes, forbidden opcodes),
///         this is 8 bytes of raw EVM that passes the sandbox opcode scan.
///
///         Bytecode layout (8 bytes):
///
///           60 01     PUSH1 0x01   (true)
///           5F        PUSH0        (memory offset 0)
///           52        MSTORE       (mem[0] = 1)
///           60 20     PUSH1 0x20   (32 bytes)
///           5F        PUSH0        (memory offset 0)
///           F3        RETURN       (return mem[0..32])
///
///         The sandbox calls this with calldata (account, keyId, hash, data).
///         We ignore all inputs and return true unconditionally.
///
///         WARNING: An AlwaysValid key authorizes ANY transaction for the account.
///         Only use with `disableGasPayment = true` for keyless relay patterns.
library AlwaysValidSandbox {
    /// @notice Runtime bytecode for the sandbox verifier (8 bytes).
    function bytecode() internal pure returns (bytes memory) {
        return hex"6001" //  PUSH1 1        (true)
            hex"5f" //  PUSH0          (offset)
            hex"52" //  MSTORE
            hex"6020" //  PUSH1 32       (size)
            hex"5f" //  PUSH0          (offset)
            hex"f3"; //  RETURN
    }

    /// @notice Deployment code: 14-byte loader + 8-byte runtime.
    function deploymentCode() internal pure returns (bytes memory) {
        bytes memory runtime = bytecode();
        uint16 n = uint16(runtime.length);
        return abi.encodePacked(
            bytes1(0x61),
            n, // PUSH2 n
            bytes1(0x60),
            bytes1(0x0E), // PUSH1 14
            bytes1(0x60),
            bytes1(0x00), // PUSH1 0
            bytes1(0x39), // CODECOPY
            bytes1(0x61),
            n, // PUSH2 n
            bytes1(0x60),
            bytes1(0x00), // PUSH1 0
            bytes1(0xF3), // RETURN
            runtime
        );
    }

    /// @notice Deploy via CREATE2.
    function deploy(bytes32 salt) internal returns (address deployed) {
        bytes memory code = deploymentCode();
        assembly {
            deployed := create2(0, add(code, 0x20), mload(code), salt)
        }
        require(deployed != address(0), "AlwaysValidSandbox: CREATE2 failed");
    }
}
