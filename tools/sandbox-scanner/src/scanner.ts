/**
 * EIP-8130 sandbox bytecode scanner.
 *
 * Analyses EVM bytecode to determine if it's safe to run inside the 8130
 * sandbox. Only opcodes that break determinism are forbidden.
 * Solidity-compiled contracts can pass.
 *
 * Spec limits (enforced at runtime, checked here statically):
 *   - Bytecode size: < 8 KB
 *   - Gas budget:    100,000
 *   - Hard kill:     5 ms wall-clock
 *   - Runtime tracks (codehash) → (avg_gas, fail_rate)
 *   - Bytecode analysis is performed once per unique codehash
 */

import { OPCODES, PRECOMPILES, type OpcodeInfo, type OpcodeStatus } from './opcodes.js';

// ─── Spec Limits ─────────────────────────────────────────────────────────────

export const MAX_BYTECODE_SIZE = 8192;  // 8 KB
export const GAS_BUDGET = 100_000;
export const HARD_KILL_MS = 5;

// ─── Types ───────────────────────────────────────────────────────────────────

export interface Instruction {
  offset: number;
  opcodeByte: number;
  opcode: OpcodeInfo | null;
  immediate: Uint8Array;
}

export interface ForbiddenHit {
  offset: number;
  name: string;
  reason: string;
  inMetadata: boolean;
}

export interface StaticCallHit {
  offset: number;
  target: number | null;
  precompileName: string | null;
  resolved: boolean;
}

export interface ScanResult {
  bytecodeSize: number;
  is7702Delegation: boolean;
  delegationTarget: string | null;
  codeSize: number;
  metadataSize: number;
  exceedsSizeLimit: boolean;
  exceedsGasBudget: boolean;
  forbidden: ForbiddenHit[];
  forbiddenInCode: ForbiddenHit[];
  staticcalls: StaticCallHit[];
  allStaticCallsSafe: boolean;
  hasLoops: boolean;
  backEdges: [number, number][];
  hasDynamicJumps: boolean;
  dynamicJumpCount: number;
  instructionCount: number;
  uniqueOpcodes: number;
  maxGasEstimate: number;
  verdict: 'safe' | 'unsafe' | 'conditional';
  verdictReasons: string[];
}

// ─── EIP-7702 Delegation Detection ───────────────────────────────────────────

const EIP_7702_PREFIX = new Uint8Array([0xef, 0x01, 0x00]);
const EIP_7702_LENGTH = 23; // 3-byte prefix + 20-byte address

/**
 * Detect EIP-7702 delegation designators. An account whose code is set to
 * 0xef0100 || <20-byte address> is delegating execution to another address.
 * This is NOT valid sandbox verifier bytecode.
 */
export function is7702Delegation(bytecode: Uint8Array): { delegation: boolean; target: string | null } {
  if (bytecode.length !== EIP_7702_LENGTH) return { delegation: false, target: null };
  for (let i = 0; i < EIP_7702_PREFIX.length; i++) {
    if (bytecode[i] !== EIP_7702_PREFIX[i]) return { delegation: false, target: null };
  }
  const addr = Array.from(bytecode.slice(3))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  return { delegation: true, target: `0x${addr}` };
}

// ─── Disassembly ─────────────────────────────────────────────────────────────

export function disassemble(bytecode: Uint8Array, start = 0): Instruction[] {
  const instructions: Instruction[] = [];
  let i = start;
  while (i < bytecode.length) {
    const byte = bytecode[i]!;
    const opcode = OPCODES[byte] ?? null;
    const immSize = opcode?.immediateBytes ?? 0;
    const immediate = bytecode.slice(i + 1, i + 1 + immSize);
    instructions.push({ offset: i, opcodeByte: byte, opcode, immediate });
    i += 1 + immSize;
  }
  return instructions;
}

// ─── Solidity Metadata Detection ─────────────────────────────────────────────

/**
 * Detect the Solidity CBOR metadata appended to bytecode.
 * The last 2 bytes encode the metadata length. We validate that the
 * metadata region starts with a CBOR map header (0xA0–0xBF).
 */
export function detectMetadataBoundary(bytecode: Uint8Array): number {
  if (bytecode.length < 4) return bytecode.length;

  const lenHi = bytecode[bytecode.length - 2]!;
  const lenLo = bytecode[bytecode.length - 1]!;
  const metaLen = (lenHi << 8) | lenLo;
  const metaStart = bytecode.length - 2 - metaLen;

  if (metaStart <= 0 || metaStart >= bytecode.length) return bytecode.length;

  const firstByte = bytecode[metaStart]!;
  if (firstByte >= 0xA0 && firstByte <= 0xBF) return metaStart;

  return bytecode.length;
}

// ─── Reachability Analysis ───────────────────────────────────────────────────

/**
 * Compute the set of reachable instruction offsets via worklist-based analysis.
 *
 * Starting from the first instruction, follow fall-through and resolved jump
 * targets. For dynamic jumps (target can't be statically resolved), conservatively
 * add ALL JUMPDEST offsets as potentially reachable. This correctly excludes
 * embedded data sections (curve constants, immutables) that appear after the
 * last INVALID/REVERT but before the CBOR metadata.
 */
function computeReachability(instructions: Instruction[], cborStart: number): Set<number> {
  const byOffset = new Map<number, number>();
  for (let i = 0; i < instructions.length; i++) {
    byOffset.set(instructions[i]!.offset, i);
  }

  // Only consider JUMPDESTs within the code section (before CBOR metadata).
  // Metadata bytes can coincidentally be 0x5B and shouldn't be treated as code.
  const jumpdests = new Set<number>();
  for (const inst of instructions) {
    if (inst.opcodeByte === 0x5B && inst.offset < cborStart) jumpdests.add(inst.offset);
  }

  const reachable = new Set<number>();
  const worklist: number[] = [];
  let dynamicSeen = false;

  if (instructions.length > 0) worklist.push(instructions[0]!.offset);

  while (worklist.length > 0) {
    const offset = worklist.pop()!;
    if (reachable.has(offset)) continue;

    const idx = byOffset.get(offset);
    if (idx === undefined) continue;

    reachable.add(offset);
    const inst = instructions[idx]!;
    const byte = inst.opcodeByte;

    // Terminal: no fall-through
    if (byte === 0x00 || byte === 0xF3 || byte === 0xFD || byte === 0xFE) continue;

    if (byte === 0x56) { // JUMP — follow target only
      const target = resolveJumpTarget(instructions, idx);
      if (target !== null) {
        worklist.push(target);
      } else if (!dynamicSeen) {
        dynamicSeen = true;
        for (const jd of jumpdests) worklist.push(jd);
      }
      continue;
    }

    if (byte === 0x57) { // JUMPI — fall-through + target
      if (idx + 1 < instructions.length) worklist.push(instructions[idx + 1]!.offset);
      const target = resolveJumpTarget(instructions, idx);
      if (target !== null) {
        worklist.push(target);
      } else if (!dynamicSeen) {
        dynamicSeen = true;
        for (const jd of jumpdests) worklist.push(jd);
      }
      continue;
    }

    // Normal: fall through
    if (idx + 1 < instructions.length) worklist.push(instructions[idx + 1]!.offset);
  }

  return reachable;
}

function resolveJumpTarget(instructions: Instruction[], jumpIdx: number): number | null {
  if (jumpIdx <= 0) return null;
  const prev = instructions[jumpIdx - 1]!;
  if (prev.opcode?.name.startsWith('PUSH') && prev.opcode.name !== 'PUSH0') {
    return immToNumber(prev.immediate);
  }
  return null;
}

// ─── Forbidden Opcode Scan ───────────────────────────────────────────────────

export function findForbidden(
  instructions: Instruction[],
  reachable: Set<number>,
): ForbiddenHit[] {
  const hits: ForbiddenHit[] = [];
  for (const inst of instructions) {
    const isReachable = reachable.has(inst.offset);
    const status = inst.opcode?.status;
    if (status === 'forbidden') {
      hits.push({
        offset: inst.offset,
        name: inst.opcode!.name,
        reason: inst.opcode!.reason!,
        inMetadata: !isReachable,
      });
    }
    if (!inst.opcode && isReachable) {
      hits.push({
        offset: inst.offset,
        name: `UNKNOWN_0x${inst.opcodeByte.toString(16).padStart(2, '0')}`,
        reason: 'undefined opcode',
        inMetadata: false,
      });
    }
  }
  return hits;
}

// ─── STATICCALL Target Resolution ────────────────────────────────────────────

/**
 * For each STATICCALL, try to resolve the target address.
 *
 * Strategy:
 *   1. Stack-tracking backward scan (60 instructions) — precise when it works
 *   2. Heuristic fallback — find the nearest PUSH of a known precompile address
 *      within 80 instructions before the STATICCALL. Solidity always pushes
 *      precompile addresses as small constants, so this catches what the stack
 *      tracker misses due to complex ABI-encoding setup.
 */
export function resolveStaticCalls(instructions: Instruction[]): StaticCallHit[] {
  const hits: StaticCallHit[] = [];

  for (let idx = 0; idx < instructions.length; idx++) {
    const inst = instructions[idx]!;
    if (inst.opcodeByte !== 0xFA) continue; // not STATICCALL

    let target: number | null = null;

    // Pass 1: stack-tracking backward scan
    let stackPos = 0;
    for (let b = idx - 1; b >= 0 && b >= idx - 60; b--) {
      const prev = instructions[b]!;
      if (!prev.opcode) break;

      const name = prev.opcode.name;

      if (name === 'GAS') {
        stackPos++;
        continue;
      }

      if (name.startsWith('PUSH') && name !== 'PUSH0') {
        if (stackPos === 1) {
          target = immToNumber(prev.immediate);
          break;
        }
        stackPos++;
        continue;
      }
      if (name === 'PUSH0') {
        if (stackPos === 1) { target = 0; break; }
        stackPos++;
        continue;
      }

      if (name.startsWith('DUP') || name.startsWith('SWAP')) {
        stackPos++;
        continue;
      }

      stackPos += (prev.opcode.stackOut - prev.opcode.stackIn);
      if (stackPos > 15) break;
    }

    // Pass 2: heuristic fallback — scan for nearest precompile-valued PUSH
    if (target === null) {
      for (let b = idx - 1; b >= 0 && b >= idx - 120; b--) {
        const prev = instructions[b]!;
        if (!prev.opcode) continue;
        if (prev.opcode.name.startsWith('PUSH') && prev.opcode.name !== 'PUSH0' && prev.immediate) {
          const val = immToNumber(prev.immediate);
          if (PRECOMPILES[val] !== undefined) {
            target = val;
            break;
          }
        }
      }
    }

    const precompileName = target !== null ? (PRECOMPILES[target] ?? null) : null;
    hits.push({
      offset: inst.offset,
      target,
      precompileName,
      resolved: target !== null,
    });
  }

  return hits;
}

function immToNumber(imm: Uint8Array): number {
  let val = 0;
  for (const b of imm) val = val * 256 + b;
  return val;
}

// ─── Loop Detection ──────────────────────────────────────────────────────────

interface LoopResult {
  hasLoops: boolean;
  backEdges: [number, number][];
  hasDynamicJumps: boolean;
  dynamicJumpCount: number;
}

/**
 * Detect loops via backward jump analysis.
 * A backward jump (target offset < source offset) indicates a potential loop.
 */
export function detectLoops(instructions: Instruction[]): LoopResult {
  const jumpdests = new Set<number>();
  for (const inst of instructions) {
    if (inst.opcodeByte === 0x5B) jumpdests.add(inst.offset);
  }

  const backEdges: [number, number][] = [];
  let dynamicJumpCount = 0;

  for (let i = 0; i < instructions.length; i++) {
    const inst = instructions[i]!;
    if (inst.opcodeByte !== 0x56 && inst.opcodeByte !== 0x57) continue; // JUMP or JUMPI

    // Try to resolve jump target from preceding PUSH
    const prev = i > 0 ? instructions[i - 1] : null;
    if (prev?.opcode?.name.startsWith('PUSH') && prev.opcode.name !== 'PUSH0') {
      const target = immToNumber(prev.immediate);
      if (target < inst.offset && jumpdests.has(target)) {
        backEdges.push([inst.offset, target]);
      }
    } else if (prev?.opcode?.name === 'PUSH0') {
      // PUSH0 + JUMP → target 0, which is backward only if jump is past 0
      if (inst.offset > 0 && jumpdests.has(0)) {
        backEdges.push([inst.offset, 0]);
      }
    } else {
      dynamicJumpCount++;
    }
  }

  return {
    hasLoops: backEdges.length > 0,
    backEdges,
    hasDynamicJumps: dynamicJumpCount > 0,
    dynamicJumpCount,
  };
}

// ─── Gas Estimation ──────────────────────────────────────────────────────────

/** Sum of base gas costs for reachable instructions. Upper bound. */
function estimateGas(instructions: Instruction[], _unused: number): number {
  let total = 0;
  for (const inst of instructions) {
    total += inst.opcode?.gas ?? 0;
  }
  return total;
}

// ─── Main Scanner ────────────────────────────────────────────────────────────

export function scan(bytecode: Uint8Array): ScanResult {
  const delegation = is7702Delegation(bytecode);
  if (delegation.delegation) {
    return {
      bytecodeSize: bytecode.length,
      is7702Delegation: true,
      delegationTarget: delegation.target,
      codeSize: 0,
      metadataSize: 0,
      exceedsSizeLimit: false,
      exceedsGasBudget: false,
      forbidden: [],
      forbiddenInCode: [],
      staticcalls: [],
      allStaticCallsSafe: true,
      hasLoops: false,
      backEdges: [],
      hasDynamicJumps: false,
      dynamicJumpCount: 0,
      instructionCount: 0,
      uniqueOpcodes: 0,
      maxGasEstimate: 0,
      verdict: 'unsafe',
      verdictReasons: [`EIP-7702 delegation designator → ${delegation.target} (not verifier bytecode)`],
    };
  }

  const cborStart = detectMetadataBoundary(bytecode);
  const instructions = disassemble(bytecode);

  // Reachability analysis: only consider instructions that are actually
  // reachable from the entry point. This correctly excludes:
  //   - Solidity CBOR metadata (appended data, never executed)
  //   - Embedded data sections (curve constants, immutables after INVALID)
  //   - Dead code
  const reachable = computeReachability(instructions, cborStart);
  const metadataSize = bytecode.length - cborStart;
  const reachableInstructions = instructions.filter(i => reachable.has(i.offset));

  const forbidden = findForbidden(instructions, reachable);
  const forbiddenInCode = forbidden.filter(h => !h.inMetadata);

  const staticcalls = resolveStaticCalls(reachableInstructions);
  const allStaticCallsSafe = staticcalls.length === 0 ||
    staticcalls.every(s => s.resolved && s.precompileName !== null);

  const loops = detectLoops(reachableInstructions);
  const maxGasEstimate = estimateGas(reachableInstructions, bytecode.length);

  const uniqueOpcodes = new Set(reachableInstructions.map(i => i.opcodeByte)).size;

  const exceedsSizeLimit = bytecode.length > MAX_BYTECODE_SIZE;
  const exceedsGasBudget = maxGasEstimate > GAS_BUDGET;

  // Build verdict:
  //   SAFE:        within spec limits, no forbidden opcodes, STATICCALL only to precompiles
  //   CONDITIONAL: no forbidden opcodes, but unresolved STATICCALL targets (runtime check)
  //   UNSAFE:      exceeds spec limits, forbidden opcodes, or STATICCALL to non-precompile
  const verdictReasons: string[] = [];
  let verdict: 'safe' | 'unsafe' | 'conditional' = 'safe';

  // Spec limits
  if (exceedsSizeLimit) {
    verdictReasons.push(`bytecode ${bytecode.length.toLocaleString()}B exceeds ${MAX_BYTECODE_SIZE.toLocaleString()}B limit`);
    verdict = 'unsafe';
  } else {
    verdictReasons.push(`bytecode ${bytecode.length.toLocaleString()}B within ${MAX_BYTECODE_SIZE.toLocaleString()}B limit`);
  }

  if (exceedsGasBudget) {
    verdictReasons.push(`gas estimate ~${maxGasEstimate.toLocaleString()} exceeds ${GAS_BUDGET.toLocaleString()} budget`);
    verdict = 'unsafe';
  } else {
    verdictReasons.push(`gas estimate ~${maxGasEstimate.toLocaleString()} within ${GAS_BUDGET.toLocaleString()} budget`);
  }

  // Forbidden opcodes
  if (forbiddenInCode.length === 0) {
    verdictReasons.push('no forbidden opcodes in reachable code');
  } else {
    const names = [...new Set(forbiddenInCode.map(h => h.name))];
    verdictReasons.push(`forbidden opcodes: ${names.join(', ')}`);
    verdict = 'unsafe';
  }

  // STATICCALL targets
  if (staticcalls.length === 0) {
    verdictReasons.push('no STATICCALL (pure computation)');
  } else if (allStaticCallsSafe) {
    verdictReasons.push(`${staticcalls.length} STATICCALL(s) — all target precompiles`);
  } else {
    const unresolved = staticcalls.filter(s => !s.resolved).length;
    const nonPrecompile = staticcalls.filter(s => s.resolved && !s.precompileName).length;
    if (nonPrecompile > 0) {
      verdictReasons.push(`${nonPrecompile} STATICCALL(s) to non-precompile address`);
      verdict = 'unsafe';
    }
    if (unresolved > 0) {
      verdictReasons.push(`${unresolved} STATICCALL(s) unresolved — runtime precompile check needed`);
      if (verdict === 'safe') verdict = 'conditional';
    }
  }

  // Informational: loops, dynamic jumps
  if (!loops.hasLoops && !loops.hasDynamicJumps) {
    verdictReasons.push('provably terminates');
  } else {
    const parts: string[] = [];
    if (loops.hasLoops) parts.push(`${loops.backEdges.length} loop(s)`);
    if (loops.hasDynamicJumps) parts.push(`${loops.dynamicJumpCount} dynamic jump(s)`);
    verdictReasons.push(`${parts.join(', ')} — bounded by ${GAS_BUDGET.toLocaleString()} gas + ${HARD_KILL_MS}ms hard kill`);
  }

  return {
    bytecodeSize: bytecode.length,
    is7702Delegation: false,
    delegationTarget: null,
    codeSize: bytecode.length - metadataSize,
    metadataSize,
    exceedsSizeLimit,
    exceedsGasBudget,
    forbidden,
    forbiddenInCode,
    staticcalls,
    allStaticCallsSafe,
    hasLoops: loops.hasLoops,
    backEdges: loops.backEdges,
    hasDynamicJumps: loops.hasDynamicJumps,
    dynamicJumpCount: loops.dynamicJumpCount,
    instructionCount: reachableInstructions.length,
    uniqueOpcodes,
    maxGasEstimate,
    verdict,
    verdictReasons,
  };
}
