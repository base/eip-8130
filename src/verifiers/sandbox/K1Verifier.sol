// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice Hand-written EIP-8130 sandbox verifier for secp256k1 ECDSA.
///
///         Equivalent to K1Verifier.sol but written as raw EVM bytecode
///         using only sandbox-allowed opcodes.
///
///         Implements: verify(bytes32 hash, bytes data)
///           1. Extracts (r, s, v) from signature data
///           2. STATICCALL ecrecover precompile (0x01)
///           3. Returns ownerId = bytes32(bytes20(recovered)) or bytes32(0)
///
///         Calldata layout (ABI-encoded verify(bytes32,bytes)):
///           0x00  selector      (4 bytes, ignored)
///           0x04  hash          (bytes32)
///           0x24  data offset   (uint256, relative to 0x04)
///           ...   data length   (uint256)
///           ...   r || s || v   (65 bytes — standard ECDSA signature)
///
///         Memory layout for ecrecover:
///           mem[0x00] = hash
///           mem[0x20] = v
///           mem[0x40] = r
///           mem[0x60] = s
///           mem[0x80] = recovered address (output)
///
///         Bytecode (74 bytes):
///
///           ┌─ ecrecover input setup (34 bytes) ────────────────────┐
///           │  60 04 35 5F 52          hash → mem[0x00]             │
///           │  60 24 35 60 24 01       dataStart = off + 0x24       │
///           │  80 35 60 40 52          r → mem[0x40]                │
///           │  80 60 20 01 35 60 60 52 s → mem[0x60]                │
///           │  60 40 01 35 60 F8 1C    extract v byte               │
///           │  60 20 52                v → mem[0x20]                │
///           └───────────────────────────────────────────────────────┘
///           ┌─ STATICCALL ecrecover (15 bytes) ─────────────────────┐
///           │  60 20 60 80 60 80 5F    ret(32,0x80) args(128,0)     │
///           │  60 01 5A FA             ecrecover(0x01)              │
///           │  15 60 42 57             fail if !success             │
///           └───────────────────────────────────────────────────────┘
///           ┌─ build ownerId + return (17 bytes) ───────────────────┐
///           │  60 80 51                load recovered address       │
///           │  80 15 60 42 57          fail if address(0)           │
///           │  60 60 1B                SHL 96 (left-align to 20b)   │
///           │  5F 52                   MSTORE(0, ownerId)           │
///           │  60 20 5F F3             RETURN(0, 32)                │
///           └───────────────────────────────────────────────────────┘
///           ┌─ fail path (8 bytes) ─────────────────────────────────┐
///           │  5B                      JUMPDEST (0x42)              │
///           │  5F 5F 52                mem[0] = 0                   │
///           │  60 20 5F F3             return bytes32(0)            │
///           └───────────────────────────────────────────────────────┘
library K1Sandbox {
    /// @notice Runtime bytecode for the sandboxed K1 verifier.
    function bytecode() internal pure returns (bytes memory) {
        return
            // ── prepare ecrecover(hash, v, r, s) in memory ──
            hex"6004355F52" // hash → mem[0x00]
            hex"602435602401" // dataStart = offset + 0x24
            hex"8035604052" // r → mem[0x40]
            hex"8060200135606052" // s → mem[0x60]
            hex"60400135" // load v byte
            hex"60F81C" // SHR 248 (extract v)
            hex"602052" // v → mem[0x20]
            // ── STATICCALL ecrecover precompile ──
            hex"6020608060805F" // ret(32,0x80) args(128,0)
            hex"60015AFA" // STATICCALL(gas, 0x01, ...)
            hex"15604257" // fail if !success → JUMPDEST at 0x42
            // ── build ownerId = bytes32(bytes20(recovered)) ──
            hex"608051" // MLOAD(0x80) → recovered
            hex"8015604257" // fail if recovered == 0 → JUMPDEST at 0x42
            hex"60601B" // SHL 96 (left-align address to bytes32)
            hex"5F52" // MSTORE(0, ownerId)
            hex"60205FF3" // RETURN(0, 32)
            // ── fail: return bytes32(0) ──
            hex"5B" // JUMPDEST (0x42)
            hex"5F5F52" // MSTORE(0, 0)
            hex"60205FF3"; // RETURN(0, 32)
    }

    /// @notice Deployment code: 14-byte loader + runtime.
    function deploymentCode() internal pure returns (bytes memory) {
        bytes memory runtime = bytecode();
        uint16 n = uint16(runtime.length);
        return abi.encodePacked(
            bytes1(0x61),
            n, // PUSH2 n
            bytes1(0x60),
            bytes1(0x0E), // PUSH1 14 (loader size)
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
        require(deployed != address(0), "K1Sandbox: CREATE2 failed");
    }
}
