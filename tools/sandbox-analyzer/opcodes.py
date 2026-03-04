"""EVM opcode definitions for EIP-8130 sandbox verifier analysis.

Each opcode is classified as allowed, forbidden, or restricted (STATICCALL)
per the EIP-8130 sandbox rules. Gas costs are base/static costs from the
Cancun hardfork; dynamic components (memory expansion, input-dependent
precompile costs) are flagged separately.
"""

from dataclasses import dataclass
from enum import Enum


class SandboxStatus(Enum):
    ALLOWED = "allowed"
    FORBIDDEN = "forbidden"
    RESTRICTED = "restricted"  # STATICCALL: allowed only to precompile targets


@dataclass(frozen=True)
class OpcodeInfo:
    code: int
    name: str
    stack_in: int
    stack_out: int
    base_gas: int
    immediate_size: int
    sandbox: SandboxStatus
    category: str
    dynamic_gas: bool = False
    min_stack_depth: int = 0  # DUPn/SWAPn need deeper stacks than stack_in implies


OPCODES: dict[int, OpcodeInfo] = {}


def _op(code, name, si, so, gas, imm, sb, cat, dyn=False, min_depth=0):
    OPCODES[code] = OpcodeInfo(code, name, si, so, gas, imm, sb, cat, dyn, min_depth or si)


A = SandboxStatus.ALLOWED
F = SandboxStatus.FORBIDDEN
R = SandboxStatus.RESTRICTED

# ── Halt ──
_op(0x00, "STOP", 0, 0, 0, 0, A, "control")

# ── Arithmetic ──
_op(0x01, "ADD", 2, 1, 3, 0, A, "arithmetic")
_op(0x02, "MUL", 2, 1, 5, 0, A, "arithmetic")
_op(0x03, "SUB", 2, 1, 3, 0, A, "arithmetic")
_op(0x04, "DIV", 2, 1, 5, 0, A, "arithmetic")
_op(0x05, "SDIV", 2, 1, 5, 0, A, "arithmetic")
_op(0x06, "MOD", 2, 1, 5, 0, A, "arithmetic")
_op(0x07, "SMOD", 2, 1, 5, 0, A, "arithmetic")
_op(0x08, "ADDMOD", 3, 1, 8, 0, A, "arithmetic")
_op(0x09, "MULMOD", 3, 1, 8, 0, A, "arithmetic")
_op(0x0A, "EXP", 2, 1, 10, 0, A, "arithmetic", dyn=True)
_op(0x0B, "SIGNEXTEND", 2, 1, 5, 0, A, "arithmetic")

# ── Comparison ──
_op(0x10, "LT", 2, 1, 3, 0, A, "comparison")
_op(0x11, "GT", 2, 1, 3, 0, A, "comparison")
_op(0x12, "SLT", 2, 1, 3, 0, A, "comparison")
_op(0x13, "SGT", 2, 1, 3, 0, A, "comparison")
_op(0x14, "EQ", 2, 1, 3, 0, A, "comparison")
_op(0x15, "ISZERO", 1, 1, 3, 0, A, "comparison")

# ── Bitwise ──
_op(0x16, "AND", 2, 1, 3, 0, A, "bitwise")
_op(0x17, "OR", 2, 1, 3, 0, A, "bitwise")
_op(0x18, "XOR", 2, 1, 3, 0, A, "bitwise")
_op(0x19, "NOT", 1, 1, 3, 0, A, "bitwise")
_op(0x1A, "BYTE", 2, 1, 3, 0, A, "bitwise")
_op(0x1B, "SHL", 2, 1, 3, 0, A, "bitwise")
_op(0x1C, "SHR", 2, 1, 3, 0, A, "bitwise")
_op(0x1D, "SAR", 2, 1, 3, 0, A, "bitwise")

# ── Crypto ──
_op(0x20, "KECCAK256", 2, 1, 30, 0, A, "crypto", dyn=True)

# ── Environment — all forbidden in sandbox ──
_op(0x30, "ADDRESS", 0, 1, 2, 0, F, "environment")
_op(0x31, "BALANCE", 1, 1, 2600, 0, F, "environment")
_op(0x32, "ORIGIN", 0, 1, 2, 0, F, "environment")
_op(0x33, "CALLER", 0, 1, 2, 0, F, "environment")
_op(0x34, "CALLVALUE", 0, 1, 2, 0, F, "environment")

# ── Calldata — allowed ──
_op(0x35, "CALLDATALOAD", 1, 1, 3, 0, A, "calldata")
_op(0x36, "CALLDATASIZE", 0, 1, 2, 0, A, "calldata")
_op(0x37, "CALLDATACOPY", 3, 0, 3, 0, A, "calldata", dyn=True)

# ── Code / ext — forbidden ──
_op(0x38, "CODESIZE", 0, 1, 2, 0, F, "environment")
_op(0x39, "CODECOPY", 3, 0, 3, 0, F, "environment")
_op(0x3A, "GASPRICE", 0, 1, 2, 0, F, "environment")
_op(0x3B, "EXTCODESIZE", 1, 1, 2600, 0, F, "environment")
_op(0x3C, "EXTCODECOPY", 4, 0, 2600, 0, F, "environment")

# ── Return data — allowed (needed after STATICCALL) ──
_op(0x3D, "RETURNDATASIZE", 0, 1, 2, 0, A, "returndata")
_op(0x3E, "RETURNDATACOPY", 3, 0, 3, 0, A, "returndata", dyn=True)

# ── Ext hash — forbidden ──
_op(0x3F, "EXTCODEHASH", 1, 1, 2600, 0, F, "environment")

# ── Block info — all forbidden ──
_op(0x40, "BLOCKHASH", 1, 1, 20, 0, F, "block")
_op(0x41, "COINBASE", 0, 1, 2, 0, F, "block")
_op(0x42, "TIMESTAMP", 0, 1, 2, 0, F, "block")
_op(0x43, "NUMBER", 0, 1, 2, 0, F, "block")
_op(0x44, "PREVRANDAO", 0, 1, 2, 0, F, "block")
_op(0x45, "GASLIMIT", 0, 1, 2, 0, F, "block")
_op(0x46, "CHAINID", 0, 1, 2, 0, F, "block")
_op(0x47, "SELFBALANCE", 0, 1, 5, 0, F, "block")
_op(0x48, "BASEFEE", 0, 1, 2, 0, F, "block")
_op(0x49, "BLOBHASH", 1, 1, 3, 0, F, "block")
_op(0x4A, "BLOBBASEFEE", 0, 1, 2, 0, F, "block")

# ── Stack / Memory / Storage ──
_op(0x50, "POP", 1, 0, 2, 0, A, "stack")
_op(0x51, "MLOAD", 1, 1, 3, 0, A, "memory", dyn=True)
_op(0x52, "MSTORE", 2, 0, 3, 0, A, "memory", dyn=True)
_op(0x53, "MSTORE8", 2, 0, 3, 0, A, "memory", dyn=True)
_op(0x54, "SLOAD", 1, 1, 2100, 0, F, "storage")
_op(0x55, "SSTORE", 2, 0, 5000, 0, F, "storage")

# ── Control ──
_op(0x56, "JUMP", 1, 0, 8, 0, A, "control")
_op(0x57, "JUMPI", 2, 0, 10, 0, A, "control")
_op(0x58, "PC", 0, 1, 2, 0, A, "control")
_op(0x59, "MSIZE", 0, 1, 2, 0, A, "memory")
_op(0x5A, "GAS", 0, 1, 2, 0, A, "control")
_op(0x5B, "JUMPDEST", 0, 0, 1, 0, A, "control")

# ── Transient storage — forbidden ──
_op(0x5C, "TLOAD", 1, 1, 100, 0, F, "storage")
_op(0x5D, "TSTORE", 2, 0, 100, 0, F, "storage")

# ── MCOPY — allowed (memory-to-memory) ──
_op(0x5E, "MCOPY", 3, 0, 3, 0, A, "memory", dyn=True)

# ── PUSH0 ──
_op(0x5F, "PUSH0", 0, 1, 2, 0, A, "stack")

# ── PUSH1–PUSH32 ──
for _i in range(1, 33):
    _op(0x5F + _i, f"PUSH{_i}", 0, 1, 3, _i, A, "stack")

# ── DUP1–DUP16 ──
for _i in range(1, 17):
    _op(0x7F + _i, f"DUP{_i}", 0, 1, 3, 0, A, "stack", min_depth=_i)

# ── SWAP1–SWAP16 ──
for _i in range(1, 17):
    _op(0x8F + _i, f"SWAP{_i}", 0, 0, 3, 0, A, "stack", min_depth=_i + 1)

# ── LOG0–LOG4 — forbidden ──
for _i in range(5):
    _op(0xA0 + _i, f"LOG{_i}", _i + 2, 0, 375, 0, F, "logging")

# ── System ──
_op(0xF0, "CREATE", 3, 1, 32000, 0, F, "system")
_op(0xF1, "CALL", 7, 1, 2600, 0, F, "system")
_op(0xF2, "CALLCODE", 7, 1, 2600, 0, F, "system")
_op(0xF3, "RETURN", 2, 0, 0, 0, A, "control")
_op(0xF4, "DELEGATECALL", 6, 1, 2600, 0, F, "system")
_op(0xF5, "CREATE2", 4, 1, 32000, 0, F, "system")
_op(0xFA, "STATICCALL", 6, 1, 100, 0, R, "system", dyn=True)
_op(0xFD, "REVERT", 2, 0, 0, 0, A, "control")
_op(0xFE, "INVALID", 0, 0, 0, 0, A, "control")
_op(0xFF, "SELFDESTRUCT", 1, 0, 5000, 0, F, "system")


# ── Precompile addresses (allowlisted for STATICCALL in sandbox) ──

PRECOMPILES: dict[int, str] = {
    0x01: "ecrecover",
    0x02: "SHA-256",
    0x03: "RIPEMD-160",
    0x04: "identity",
    0x05: "modexp",
    0x06: "ecAdd (bn128)",
    0x07: "ecMul (bn128)",
    0x08: "ecPairing (bn128)",
    0x09: "blake2f",
    0x0A: "KZG point evaluation",
    # EIP-2537 BLS12-381 precompiles (Pectra)
    0x0B: "BLS12_G1ADD",
    0x0C: "BLS12_G1MUL",
    0x0D: "BLS12_G1MULTIEXP",
    0x0E: "BLS12_G2ADD",
    0x0F: "BLS12_G2MUL",
    0x10: "BLS12_G2MULTIEXP",
    0x11: "BLS12_PAIRING",
    0x12: "BLS12_MAP_FP_TO_G1",
    0x13: "BLS12_MAP_FP2_TO_G2",
    # RIP-7212 P256
    0x100: "P256VERIFY",
}

PRECOMPILE_BASE_GAS: dict[int, int] = {
    0x01: 3_000,
    0x02: 60,
    0x03: 600,
    0x04: 15,
    0x05: 200,       # modexp base; actual cost is dynamic
    0x06: 150,
    0x07: 6_000,
    0x08: 45_000,    # ecPairing base; +34k per pair
    0x09: 0,         # blake2f: cost = rounds parameter
    0x0A: 50_000,
    0x0B: 500,
    0x0C: 12_000,
    0x0D: 12_000,    # base; scales with input
    0x0E: 800,
    0x0F: 45_000,
    0x10: 45_000,    # base; scales with input
    0x11: 65_000,    # base; +43k per pair
    0x12: 5_500,
    0x13: 23_800,
    0x100: 3_450,
}
