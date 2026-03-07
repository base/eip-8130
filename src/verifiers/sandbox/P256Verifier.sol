// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice Hand-written EIP-8130 sandbox verifier for P-256 (secp256r1) ECDSA.
///
///         Equivalent to P256Verifier.sol but written as raw EVM bytecode
///         using only sandbox-allowed opcodes.
///
///         Implements: verify(bytes32 hash, bytes data)
///           1. Extracts (r, s, x, y) from data
///           2. Computes ownerId = keccak256(x || y)
///           3. STATICCALL P256VERIFY precompile (0x100)
///           4. Returns ownerId or bytes32(0)
///
///         Calldata layout (ABI-encoded verify(bytes32,bytes)):
///           0x00  selector      (4 bytes, ignored)
///           0x04  hash          (bytes32)
///           0x24  data offset   (uint256, relative to 0x04)
///           ...   data length   (uint256)
///           ...   r (32) || s (32) || x (32) || y (32) || pre_hash (1)
///
///         Memory layout for P256VERIFY:
///           mem[0x00] = hash    (32 bytes)
///           mem[0x20] = r       (32 bytes)
///           mem[0x40] = s       (32 bytes)
///           mem[0x60] = x       (32 bytes)
///           mem[0x80] = y       (32 bytes)
///           mem[0xA0] = result  (32 bytes, output from precompile)
///
///         ownerId is computed as keccak256(mem[0x60..0x9F]) = keccak256(x || y).
///
///         Bytecode (82 bytes):
///
///           ┌─ P256VERIFY input setup (39 bytes) ───────────────────┐
///           │  60 04 35 5F 52          hash → mem[0x00]             │
///           │  60 24 35 60 24 01       dataStart = off + 0x24       │
///           │  80 35 60 20 52          r → mem[0x20]                │
///           │  80 60 20 01 35 60 40 52 s → mem[0x40]                │
///           │  80 60 40 01 35 60 60 52 x → mem[0x60]                │
///           │  60 60 01 35 60 80 52    y → mem[0x80]                │
///           └───────────────────────────────────────────────────────┘
///           ┌─ keccak256(x || y) → ownerId (5 bytes) ──────────────┐
///           │  60 40 60 60 20          SHA3(mem[0x60], 64)          │
///           └───────────────────────────────────────────────────────┘
///           ┌─ STATICCALL P256VERIFY (12 bytes) ────────────────────┐
///           │  60 20 60 A0 60 A0 5F    ret(32,0xA0) args(160,0)    │
///           │  61 01 00 5A FA          P256VERIFY(0x100)            │
///           └───────────────────────────────────────────────────────┘
///           ┌─ validate + return (17 bytes) ────────────────────────┐
///           │  60 A0 51 02 60 01 14    success * result == 1        │
///           │  15 60 49 57             fail if invalid              │
///           │  5F 52 60 20 5F F3       RETURN ownerId               │
///           └───────────────────────────────────────────────────────┘
///           ┌─ fail path (9 bytes) ─────────────────────────────────┐
///           │  5B                      JUMPDEST (0x49)              │
///           │  50                      POP ownerId                  │
///           │  5F 5F 52                mem[0] = 0                   │
///           │  60 20 5F F3             return bytes32(0)            │
///           └───────────────────────────────────────────────────────┘
library P256Sandbox {
    /// @notice Runtime bytecode for the sandboxed P256 verifier.
    function bytecode() internal pure returns (bytes memory) {
        return
            // ── load P256VERIFY inputs into memory ──
            hex"6004355F52" // hash → mem[0x00]
            hex"602435602401" // dataStart = offset + 0x24
            hex"8035602052" // r → mem[0x20]
            hex"8060200135604052" // s → mem[0x40]
            hex"8060400135606052" // x → mem[0x60]
            hex"60600135608052" // y → mem[0x80]
            // ── ownerId = keccak256(x || y) ──
            hex"6040606020" // SHA3(mem[0x60], 64) → ownerId on stack
            // ── STATICCALL P256VERIFY precompile ──
            hex"602060A060A05F" // ret(32,0xA0) args(160,0)
            hex"6101005AFA" // STATICCALL(gas, 0x100, ...)
            // ── check success * result == 1 ──
            hex"60A05102600114" // MLOAD(0xA0) * success == 1?
            hex"15604957" // fail if invalid → JUMPDEST at 0x49
            // ── return ownerId ──
            hex"5F52" // MSTORE(0, ownerId)
            hex"60205FF3" // RETURN(0, 32)
            // ── fail: return bytes32(0) ──
            hex"5B" // JUMPDEST (0x49)
            hex"50" // POP ownerId
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
        require(deployed != address(0), "P256Sandbox: CREATE2 failed");
    }
}
