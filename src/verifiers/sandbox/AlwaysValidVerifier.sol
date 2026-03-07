// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice Hand-written EIP-8130 sandbox verifier that always returns the ownerId
///         from data (first 32 bytes).
///
///         This is the sandbox-native equivalent of AlwaysValidVerifier.sol.
///
///         Calldata layout (ABI-encoded):
///           0x00  selector      (4 bytes, ignored)
///           0x04  hash          (bytes32, ignored)
///           0x24  data offset   (uint256, relative to 0x04)
///           ...   data length   (uint256)
///           ...   ownerId       (bytes32 — first 32 bytes of data)
///
///         Bytecode (13 bytes):
///
///           60 24     PUSH1 0x24       (data offset location in calldata)
///           35        CALLDATALOAD     (load offset value, relative to 0x04)
///           60 24     PUSH1 0x24       (0x04 ABI base + 0x20 length word)
///           01        ADD              (absolute position of first data byte)
///           35        CALLDATALOAD     (load ownerId — first 32 bytes of data)
///           5F        PUSH0            (memory offset 0)
///           52        MSTORE           (mem[0] = ownerId)
///           60 20     PUSH1 0x20       (32 bytes)
///           5F        PUSH0            (memory offset 0)
///           F3        RETURN           (return ownerId)
///
///         WARNING: An AlwaysValid owner authorizes ANY transaction for the account.
library AlwaysValidSandbox {
    /// @notice Runtime bytecode for the sandbox verifier (13 bytes).
    function bytecode() internal pure returns (bytes memory) {
        return hex"602435" // CALLDATALOAD(0x24) → data offset (relative to 0x04)
            hex"602401" // ADD 0x24 → absolute position past length word (offset + 0x04 + 0x20)
            hex"35" // CALLDATALOAD → ownerId (first 32 bytes of data)
            hex"5f" // PUSH0 (memory offset)
            hex"52" // MSTORE(0, ownerId)
            hex"6020" // PUSH1 32 (return size)
            hex"5f" // PUSH0 (memory offset)
            hex"f3"; // RETURN(0, 32)
    }

    /// @notice Deployment code: 14-byte loader + runtime.
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
