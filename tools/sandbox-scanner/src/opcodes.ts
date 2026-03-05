/**
 * EVM opcode definitions for the EIP-8130 sandbox scanner.
 *
 * Uses a NARROWER forbidden set than the current spec: only opcodes that break
 * determinism (external state, block context, side effects) are forbidden.
 * Environment opcodes like CALLVALUE, CALLER, ADDRESS are ALLOWED because the
 * sandbox provides deterministic values for them.
 */

export type OpcodeStatus = 'allowed' | 'forbidden' | 'restricted';

export interface OpcodeInfo {
  name: string;
  immediateBytes: number;
  stackIn: number;
  stackOut: number;
  gas: number;
  status: OpcodeStatus;
  reason?: string;
}

// Helpers for concise table definition
function a(name: string, imm: number, si: number, so: number, gas: number): OpcodeInfo {
  return { name, immediateBytes: imm, stackIn: si, stackOut: so, gas, status: 'allowed' };
}
function f(name: string, imm: number, si: number, so: number, gas: number, reason: string): OpcodeInfo {
  return { name, immediateBytes: imm, stackIn: si, stackOut: so, gas, status: 'forbidden', reason };
}
function r(name: string, imm: number, si: number, so: number, gas: number, reason: string): OpcodeInfo {
  return { name, immediateBytes: imm, stackIn: si, stackOut: so, gas, status: 'restricted', reason };
}

export const OPCODES: Record<number, OpcodeInfo> = {
  // ── Stop & Arithmetic ──
  0x00: a('STOP',        0, 0, 0, 0),
  0x01: a('ADD',         0, 2, 1, 3),
  0x02: a('MUL',         0, 2, 1, 5),
  0x03: a('SUB',         0, 2, 1, 3),
  0x04: a('DIV',         0, 2, 1, 5),
  0x05: a('SDIV',        0, 2, 1, 5),
  0x06: a('MOD',         0, 2, 1, 5),
  0x07: a('SMOD',        0, 2, 1, 5),
  0x08: a('ADDMOD',      0, 3, 1, 8),
  0x09: a('MULMOD',      0, 3, 1, 8),
  0x0A: a('EXP',         0, 2, 1, 10),
  0x0B: a('SIGNEXTEND',  0, 2, 1, 5),

  // ── Comparison & Bitwise ──
  0x10: a('LT',          0, 2, 1, 3),
  0x11: a('GT',          0, 2, 1, 3),
  0x12: a('SLT',         0, 2, 1, 3),
  0x13: a('SGT',         0, 2, 1, 3),
  0x14: a('EQ',          0, 2, 1, 3),
  0x15: a('ISZERO',      0, 1, 1, 3),
  0x16: a('AND',         0, 2, 1, 3),
  0x17: a('OR',          0, 2, 1, 3),
  0x18: a('XOR',         0, 2, 1, 3),
  0x19: a('NOT',         0, 1, 1, 3),
  0x1A: a('BYTE',        0, 2, 1, 3),
  0x1B: a('SHL',         0, 2, 1, 3),
  0x1C: a('SHR',         0, 2, 1, 3),
  0x1D: a('SAR',         0, 2, 1, 3),

  // ── Keccak ──
  0x20: a('KECCAK256',   0, 2, 1, 30),

  // ── Environment — allowed in sandbox (deterministic values) ──
  0x30: a('ADDRESS',      0, 0, 1, 2),
  0x32: a('ORIGIN',       0, 0, 1, 2),
  0x33: a('CALLER',       0, 0, 1, 2),
  0x34: a('CALLVALUE',    0, 0, 1, 2),
  0x35: a('CALLDATALOAD', 0, 1, 1, 3),
  0x36: a('CALLDATASIZE', 0, 0, 1, 2),
  0x37: a('CALLDATACOPY', 0, 3, 0, 3),
  0x38: a('CODESIZE',     0, 0, 1, 2),
  0x39: a('CODECOPY',     0, 3, 0, 3),
  0x3D: a('RETURNDATASIZE', 0, 0, 1, 2),
  0x3E: a('RETURNDATACOPY', 0, 3, 0, 3),

  // ── Environment — FORBIDDEN (depends on external/mutable state) ──
  0x31: f('BALANCE',      0, 1, 1, 2600, 'reads external account balance'),
  0x3A: f('GASPRICE',     0, 0, 1, 2,    'transaction-dependent'),
  0x3B: f('EXTCODESIZE',  0, 1, 1, 2600, 'reads external contract state'),
  0x3C: f('EXTCODECOPY',  0, 4, 0, 2600, 'reads external contract state'),
  0x3F: f('EXTCODEHASH',  0, 1, 1, 2600, 'reads external contract state'),

  // ── Block context — FORBIDDEN (changes per block) ──
  0x40: f('BLOCKHASH',    0, 1, 1, 20,   'block-dependent'),
  0x41: f('COINBASE',     0, 0, 1, 2,    'block-dependent'),
  0x42: f('TIMESTAMP',    0, 0, 1, 2,    'block-dependent'),
  0x43: f('NUMBER',       0, 0, 1, 2,    'block-dependent'),
  0x44: f('PREVRANDAO',   0, 0, 1, 2,    'block-dependent'),
  0x45: f('GASLIMIT',     0, 0, 1, 2,    'block-dependent'),
  0x47: f('SELFBALANCE',  0, 0, 1, 5,    'reads own balance (mutable)'),
  0x48: f('BASEFEE',      0, 0, 1, 2,    'block-dependent'),
  0x49: f('BLOBHASH',     0, 1, 1, 3,    'block-dependent'),
  0x4A: f('BLOBBASEFEE',  0, 0, 1, 2,    'block-dependent'),

  // ── Chain ID — allowed (constant per chain) ──
  0x46: a('CHAINID',      0, 0, 1, 2),

  // ── Memory & Stack ──
  0x50: a('POP',          0, 1, 0, 2),
  0x51: a('MLOAD',        0, 1, 1, 3),
  0x52: a('MSTORE',       0, 2, 0, 3),
  0x53: a('MSTORE8',      0, 2, 0, 3),

  // ── Storage — FORBIDDEN ──
  0x54: f('SLOAD',        0, 1, 1, 2100, 'persistent state read'),
  0x55: f('SSTORE',       0, 2, 0, 5000, 'persistent state write'),

  // ── Control flow ──
  0x56: a('JUMP',         0, 1, 0, 8),
  0x57: a('JUMPI',        0, 2, 0, 10),
  0x58: a('PC',           0, 0, 1, 2),
  0x59: a('MSIZE',        0, 0, 1, 2),
  0x5A: a('GAS',          0, 0, 1, 2),
  0x5B: a('JUMPDEST',     0, 0, 0, 1),

  // ── Transient storage — FORBIDDEN ──
  0x5C: f('TLOAD',        0, 1, 1, 100,  'transient state read'),
  0x5D: f('TSTORE',       0, 2, 0, 100,  'transient state write'),

  // ── Memory copy (Cancun) ──
  0x5E: a('MCOPY',        0, 3, 0, 3),

  // ── PUSH0 (Shanghai) ──
  0x5F: a('PUSH0',        0, 0, 1, 2),

  // ── PUSH1–PUSH32 ──
  ...Object.fromEntries(
    Array.from({ length: 32 }, (_, i) => [
      0x60 + i,
      a(`PUSH${i + 1}`, i + 1, 0, 1, 3),
    ])
  ),

  // ── DUP1–DUP16 ──
  ...Object.fromEntries(
    Array.from({ length: 16 }, (_, i) => [
      0x80 + i,
      a(`DUP${i + 1}`, 0, i + 1, i + 2, 3),
    ])
  ),

  // ── SWAP1–SWAP16 ──
  ...Object.fromEntries(
    Array.from({ length: 16 }, (_, i) => [
      0x90 + i,
      a(`SWAP${i + 1}`, 0, i + 2, i + 2, 3),
    ])
  ),

  // ── LOG — FORBIDDEN (side effects) ──
  0xA0: f('LOG0', 0, 2, 0, 375, 'logging side effect'),
  0xA1: f('LOG1', 0, 3, 0, 750, 'logging side effect'),
  0xA2: f('LOG2', 0, 4, 0, 1125, 'logging side effect'),
  0xA3: f('LOG3', 0, 5, 0, 1500, 'logging side effect'),
  0xA4: f('LOG4', 0, 6, 0, 1875, 'logging side effect'),

  // ── Create — FORBIDDEN ──
  0xF0: f('CREATE',       0, 3, 1, 32000, 'contract creation'),
  0xF5: f('CREATE2',      0, 4, 1, 32000, 'contract creation'),

  // ── Calls ──
  0xF1: f('CALL',         0, 7, 1, 2600, 'external call with value'),
  0xF2: f('CALLCODE',     0, 7, 1, 2600, 'external call (callcode)'),
  0xF4: f('DELEGATECALL', 0, 6, 1, 2600, 'external call (delegatecall)'),
  0xFA: r('STATICCALL',   0, 6, 1, 2600, 'allowed — target must be precompile'),

  // ── Return & Halt ──
  0xF3: a('RETURN',       0, 2, 0, 0),
  0xFD: a('REVERT',       0, 2, 0, 0),
  0xFE: a('INVALID',      0, 0, 0, 0),
  0xFF: f('SELFDESTRUCT', 0, 1, 0, 5000, 'self-destruct side effect'),
};

/** Known Ethereum precompile addresses. */
export const PRECOMPILES: Record<number, string> = {
  0x01: 'ecrecover',
  0x02: 'SHA-256',
  0x03: 'RIPEMD-160',
  0x04: 'identity',
  0x05: 'modexp',
  0x06: 'ecAdd',
  0x07: 'ecMul',
  0x08: 'ecPairing',
  0x09: 'blake2f',
  0x0A: 'KZG',
  0x0B: 'BLS12_G1ADD',
  0x0C: 'BLS12_G1MUL',
  0x0D: 'BLS12_G1MSM',
  0x0E: 'BLS12_G2ADD',
  0x0F: 'BLS12_G2MUL',
  0x10: 'BLS12_G2MSM',
  0x11: 'BLS12_PAIRING',
  0x12: 'BLS12_MAP_FP_TO_G1',
  0x13: 'BLS12_MAP_FP2_TO_G2',
  0x100: 'P256VERIFY',
};
