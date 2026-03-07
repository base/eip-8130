/**
 * EIP-8130 sandbox executor.
 *
 * Runs verifier bytecode in a sandboxed EVM to measure actual gas consumption.
 * Optionally enforces sandbox rules (forbidden opcodes, STATICCALL targets)
 * to validate that the verifier is pure.
 *
 * Uses @ethereumjs/evm for EVM execution.
 */

import { createEVM } from '@ethereumjs/evm';
import { Common, Hardfork, Mainnet } from '@ethereumjs/common';
import { Address, hexToBytes, bytesToHex, createAddressFromString } from '@ethereumjs/util';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { PRECOMPILES } from './opcodes.js';

// ─── Constants ───────────────────────────────────────────────────────────────

export const DEFAULT_GAS_LIMIT = 100_000n;

const VERIFIER_ADDRESS = '0x0000000000000000000000000000000000008130';

const VERIFY_SELECTOR = keccak_256(
  new TextEncoder().encode('verify(address,bytes32,bytes)')
).slice(0, 4);

const FORBIDDEN_OPCODES = new Set([
  'BALANCE', 'GASPRICE', 'EXTCODESIZE', 'EXTCODECOPY', 'EXTCODEHASH',
  'BLOCKHASH', 'COINBASE', 'TIMESTAMP', 'NUMBER', 'PREVRANDAO',
  'GASLIMIT', 'SELFBALANCE', 'BASEFEE', 'BLOBHASH', 'BLOBBASEFEE',
  'SLOAD', 'SSTORE', 'TLOAD', 'TSTORE',
  'LOG0', 'LOG1', 'LOG2', 'LOG3', 'LOG4',
  'CREATE', 'CREATE2',
  'CALL', 'CALLCODE', 'DELEGATECALL',
  'SELFDESTRUCT',
]);

const PRECOMPILE_ADDRESSES = new Set(Object.keys(PRECOMPILES).map(Number));

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ExecuteOpts {
  bytecode: Uint8Array;
  account?: Uint8Array;    // 20-byte address (default: zero)
  hash?: Uint8Array;       // 32-byte hash (default: keccak256("test"))
  data?: Uint8Array;       // Verifier-specific signature data
  calldata?: Uint8Array;   // Full ABI-encoded calldata (overrides account/hash/data)
  gasLimit?: bigint;
}

export interface OpcodeHit {
  opcode: string;
  pc: number;
}

export interface StaticCallTarget {
  address: number;
  pc: number;
  isPrecompile: boolean;
}

export interface ExecuteResult {
  gasUsed: bigint;
  success: boolean;
  returnValue: Uint8Array;
  ownerId: string | null;
  error: string | null;
  forbiddenOpcodeHits: OpcodeHit[];
  staticcallTargets: StaticCallTarget[];
  sandboxSafe: boolean;
}

// ─── ABI Encoding ────────────────────────────────────────────────────────────

function padLeft(data: Uint8Array, size: number): Uint8Array {
  if (data.length >= size) return data.slice(0, size);
  const padded = new Uint8Array(size);
  padded.set(data, size - data.length);
  return padded;
}

function uint256(value: number): Uint8Array {
  const buf = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0 && v > 0; i--) {
    buf[i] = v & 0xff;
    v = Math.floor(v / 256);
  }
  return buf;
}

function padRight(data: Uint8Array, multiple: number): Uint8Array {
  const remainder = data.length % multiple;
  if (remainder === 0) return data;
  const padded = new Uint8Array(data.length + multiple - remainder);
  padded.set(data);
  return padded;
}

function concat(arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

/**
 * ABI-encode a call to verify(address, bytes32, bytes).
 */
export function encodeVerifyCall(
  account: Uint8Array,
  hash: Uint8Array,
  data: Uint8Array,
): Uint8Array {
  const encodedAccount = padLeft(account, 32);
  const encodedHash = padLeft(hash, 32);
  // Dynamic bytes: offset (3 * 32 = 96 = 0x60), then length, then padded data
  const dataOffset = uint256(96);
  const dataLength = uint256(data.length);
  const paddedData = padRight(data, 32);

  return concat([
    VERIFY_SELECTOR,
    encodedAccount,
    encodedHash,
    dataOffset,
    dataLength,
    paddedData,
  ]);
}

// ─── Execution ───────────────────────────────────────────────────────────────

/**
 * Execute verifier bytecode in a sandboxed EVM and measure gas.
 *
 * Deploys the bytecode at a synthetic address and calls verify(account, hash, data).
 * Tracks forbidden opcode usage and STATICCALL targets.
 */
export async function execute(opts: ExecuteOpts): Promise<ExecuteResult> {
  const common = new Common({ chain: Mainnet, hardfork: Hardfork.Prague });
  const evm = await createEVM({ common });

  // Deploy verifier bytecode
  const verifierAddr = createAddressFromString(VERIFIER_ADDRESS);
  await evm.stateManager.putCode(verifierAddr, opts.bytecode);

  // Build calldata
  let calldata: Uint8Array;
  if (opts.calldata) {
    calldata = opts.calldata;
  } else {
    const account = opts.account ?? new Uint8Array(20);
    const hash = opts.hash ?? keccak_256(new TextEncoder().encode('test'));
    const data = opts.data ?? new Uint8Array(0);
    calldata = encodeVerifyCall(account, hash, data);
  }

  const gasLimit = opts.gasLimit ?? DEFAULT_GAS_LIMIT;

  // Track sandbox violations
  const forbiddenOpcodeHits: OpcodeHit[] = [];
  const staticcallTargets: StaticCallTarget[] = [];

  evm.events.on('step', (event: any) => {
    const opName: string = event.opcode.name;
    const pc: number = event.pc;

    if (FORBIDDEN_OPCODES.has(opName)) {
      forbiddenOpcodeHits.push({ opcode: opName, pc });
    }

    // Track STATICCALL targets — the target address is the 2nd stack item
    // Stack layout for STATICCALL: [gas, addr, argsOffset, argsLength, retOffset, retLength]
    if (opName === 'STATICCALL' && event.stack.length >= 2) {
      const targetBigInt: bigint = event.stack[event.stack.length - 2];
      const target = Number(targetBigInt);
      staticcallTargets.push({
        address: target,
        pc,
        isPrecompile: PRECOMPILE_ADDRESSES.has(target),
      });
    }
  });

  // Execute
  const result = await evm.runCall({
    to: verifierAddr,
    data: calldata,
    gasLimit,
  });

  const execResult = result.execResult;
  const gasUsed = execResult.executionGasUsed;
  const success = !execResult.exceptionError;
  const returnValue = execResult.returnValue;
  const error = execResult.exceptionError?.error ?? null;

  // Decode ownerId from return value (bytes32)
  let ownerId: string | null = null;
  if (success && returnValue.length >= 32) {
    const ownerIdBytes = returnValue.slice(0, 32);
    const isZero = ownerIdBytes.every(b => b === 0);
    if (!isZero) {
      ownerId = '0x' + Array.from(ownerIdBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }
  }

  // Sandbox safety: no forbidden opcodes, all STATICCALLs target precompiles
  const allStaticCallsSafe = staticcallTargets.every(s => s.isPrecompile);
  const sandboxSafe = forbiddenOpcodeHits.length === 0 && allStaticCallsSafe;

  return {
    gasUsed,
    success,
    returnValue,
    ownerId,
    error,
    forbiddenOpcodeHits,
    staticcallTargets,
    sandboxSafe,
  };
}
