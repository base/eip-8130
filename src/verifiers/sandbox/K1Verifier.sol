// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice Hand-written EIP-8130 sandbox verifier for secp256k1 ECDSA.
///
///         Equivalent to K1Verifier.sol but written as raw EVM bytecode
///         using only sandbox-allowed opcodes. 101 bytes vs 938 bytes compiled.
///
///         Implements: verify(address, bytes32 keyId, bytes32 hash, bytes data)
///           1. Checks keyId is a clean address (lower 12 bytes zero), reverts if not
///           2. Extracts (r, s, v) from signature data
///           3. STATICCALL ecrecover precompile (0x01)
///           4. Verifies recovered address is non-zero and matches keyId
///           5. Returns bool result
///
///         Calldata layout (ABI-encoded):
///           0x00  selector      (4 bytes, ignored)
///           0x04  account       (address, ignored)
///           0x24  keyId         (bytes32 — address in high 20 bytes)
///           0x44  hash          (bytes32)
///           0x64  data offset   (uint256, relative to 0x04)
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
///         Bytecode (101 bytes):
///
///           ┌─ keyId clean check (26 bytes) ─────────────────────┐
///           │  60 24        PUSH1 0x24                           │
///           │  35           CALLDATALOAD      ── keyId           │
///           │  80           DUP1                                 │
///           │  6B FF(x12)   PUSH12 mask        ── lower 12 bytes │
///           │  16           AND                                  │
///           │  15           ISZERO                               │
///           │  60 19        PUSH1 0x19                           │
///           │  57           JUMPI             ── skip if clean   │
///           │  5F 5F FD     PUSH0 PUSH0 REVERT                  │
///           │  5B           JUMPDEST                             │
///           └────────────────────────────────────────────────────┘
///           ┌─ ecrecover input setup (29 bytes) ─────────────────┐
///           │  60 44 35 5F 52          hash → mem[0x00]          │
///           │  60 64 35 60 24 01       dataStart = off + 0x24    │
///           │  80 35 60 40 52          r → mem[0x40]             │
///           │  80 60 20 01 35 60 60 52 s → mem[0x60]             │
///           │  60 40 01 35 60 F8 1C    extract v byte            │
///           │  60 20 52                v → mem[0x20]             │
///           └────────────────────────────────────────────────────┘
///           ┌─ STATICCALL ecrecover (15 bytes) ──────────────────┐
///           │  60 20 60 80 60 80 5F    ret(32,0x80) args(128,0)  │
///           │  60 01 5A FA             ecrecover(0x01)           │
///           │  15 60 5D 57             fail if !success          │
///           └────────────────────────────────────────────────────┘
///           ┌─ verify + return (18 bytes) ───────────────────────┐
///           │  60 80 51                load recovered address    │
///           │  80 15 60 5D 57          fail if address(0)        │
///           │  60 60 1B                SHL 96 (align to keyId)   │
///           │  14                      EQ with keyId             │
///           │  5F 52 60 20 5F F3       return bool               │
///           └────────────────────────────────────────────────────┘
///           ┌─ fail path (8 bytes) ──────────────────────────────┐
///           │  5B                      JUMPDEST                  │
///           │  5F 5F 52                mem[0] = 0                │
///           │  60 20 5F F3             return false              │
///           └────────────────────────────────────────────────────┘
library K1Sandbox {
    /// @notice Runtime bytecode for the sandboxed K1 verifier (101 bytes).
    function bytecode() internal pure returns (bytes memory) {
        return
            // ── keyId clean check: revert if lower 12 bytes non-zero ──
            hex"602435" // CALLDATALOAD(0x24) → keyId
            hex"80" // DUP1
            hex"6BFFFFFFFFFFFFFFFFFFFFFFFF" // PUSH12 lower-12 mask
            hex"1615" // AND, ISZERO
            hex"6019" // PUSH1 0x19 (clean dest)
            hex"57" // JUMPI
            hex"5F5FFD" // PUSH0 PUSH0 REVERT
            hex"5B" // JUMPDEST
            // ── prepare ecrecover(hash, v, r, s) in memory ──
            hex"6044355F52" // hash → mem[0x00]
            hex"606435602401" // dataStart = offset + 0x24
            hex"8035604052" // r → mem[0x40]
            hex"8060200135606052" // s → mem[0x60]
            hex"60400135" // load v byte
            hex"60F81C" // SHR 248 (extract v)
            hex"602052" // v → mem[0x20]
            // ── STATICCALL ecrecover precompile ──
            hex"6020608060805F" // ret(32,0x80) args(128,0)
            hex"60015AFA" // STATICCALL(gas, 0x01, ...)
            hex"15605D57" // fail if !success
            // ── verify recovered address matches keyId ──
            hex"608051" // MLOAD(0x80) → recovered
            hex"8015605D57" // fail if recovered == 0
            hex"60601B" // SHL 96 → align to keyId
            hex"14" // EQ (recovered vs keyId)
            // ── return result ──
            hex"5F52" // MSTORE(0, result)
            hex"60205FF3" // RETURN(0, 32)
            // ── fail: return false ──
            hex"5B" // JUMPDEST
            hex"5F5F52" // MSTORE(0, 0)
            hex"60205FF3"; // RETURN(0, 32)
    }

    /// @notice Deployment code: 14-byte loader + 101-byte runtime.
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
