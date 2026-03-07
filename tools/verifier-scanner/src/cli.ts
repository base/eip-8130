#!/usr/bin/env node
/**
 * EIP-8130 Verifier Scanner — CLI
 *
 * Usage:
 *   npx tsx src/cli.ts --hex 6006568130005b...
 *   npx tsx src/cli.ts --file path/to/bytecode.hex
 *   npx tsx src/cli.ts --artifact out/K1Verifier.sol/K1Verifier.json
 *   npx tsx src/cli.ts --batch out/ [--filter '*Verifier']
 *   npx tsx src/cli.ts --hex ... --json
 *   npx tsx src/cli.ts --execute --artifact out/K1Verifier.sol/K1Verifier.json --data 0x...
 */

import { readFileSync, readdirSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve, basename, join } from 'node:path';
import { scan, MAX_BYTECODE_SIZE, GAS_BUDGET, HARD_KILL_MS, type ScanResult } from './scanner.js';
import { execute, encodeVerifyCall, DEFAULT_GAS_LIMIT, type ExecuteResult } from './sandbox.js';

// ─── Argument Parsing ────────────────────────────────────────────────────────

interface Args {
  hex?: string;
  file?: string;
  artifact?: string;
  batch?: string;
  filter?: string;
  json?: boolean;
  output?: string;
  execute?: boolean;
  account?: string;
  hash?: string;
  data?: string;
  calldata?: string;
  gasLimit?: string;
}

function parseArgs(): Args {
  const argv = process.argv.slice(2);
  const args: Args = {};
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case '--hex':       args.hex = argv[++i]; break;
      case '--file':      args.file = argv[++i]; break;
      case '--artifact':  args.artifact = argv[++i]; break;
      case '--batch':     args.batch = argv[++i]; break;
      case '--filter':    args.filter = argv[++i]; break;
      case '--json':      args.json = true; break;
      case '-o': case '--output': args.output = argv[++i]; break;
      case '--execute':   args.execute = true; break;
      case '--account':   args.account = argv[++i]; break;
      case '--hash':      args.hash = argv[++i]; break;
      case '--data':      args.data = argv[++i]; break;
      case '--calldata':  args.calldata = argv[++i]; break;
      case '--gas-limit': args.gasLimit = argv[++i]; break;
      case '--help': case '-h': printUsage(); process.exit(0);
      default:
        console.error(`Unknown argument: ${argv[i]}`);
        printUsage();
        process.exit(1);
    }
  }
  return args;
}

function printUsage(): void {
  console.log(`
EIP-8130 Verifier Scanner

Usage:
  npx tsx src/cli.ts --hex <hex>              Scan hex bytecode
  npx tsx src/cli.ts --file <path>            Scan bytecode from file
  npx tsx src/cli.ts --artifact <path>        Scan Foundry JSON artifact
  npx tsx src/cli.ts --batch <dir>            Scan all artifacts in directory
  npx tsx src/cli.ts --batch <dir> -o <dir>   Write reports to output directory

Execute (gas estimation):
  npx tsx src/cli.ts --execute --artifact <path> --data <hex>
  npx tsx src/cli.ts --execute --artifact <path> --calldata <hex>
  npx tsx src/cli.ts --execute --artifact <path> --account <addr> --hash <hex> --data <hex>

Options:
  --filter <glob>     Filter artifacts in batch mode (e.g. '*Verifier')
  --json              Output JSON instead of text
  --execute           Execute bytecode in sandbox EVM for gas measurement
  --account <addr>    Account address for verify() call (default: zero)
  --hash <hex>        Hash for verify() call (default: keccak256("test"))
  --data <hex>        Verifier-specific data for verify() call
  --calldata <hex>    Full ABI-encoded calldata (overrides account/hash/data)
  --gas-limit <n>     Gas limit for execution (default: ${DEFAULT_GAS_LIMIT})
  -o, --output        Output directory for batch reports
  -h, --help          Show this help
`);
}

// ─── Bytecode Loading ────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/i, '').replace(/\s/g, '');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function loadArtifact(path: string): { name: string; bytecode: Uint8Array } {
  const raw = readFileSync(resolve(path), 'utf-8');
  const json = JSON.parse(raw);

  const hex: string =
    json.deployedBytecode?.object ??
    json.deployedBytecode ??
    json.bytecode?.object ??
    json.bytecode;

  if (!hex || typeof hex !== 'string') {
    throw new Error(`No bytecode found in artifact: ${path}`);
  }

  const name = basename(path, '.json');
  return { name, bytecode: hexToBytes(hex) };
}

function findArtifacts(dir: string, filter?: string): string[] {
  const results: string[] = [];
  const pattern = filter
    ? new RegExp('^' + filter.replace(/\*/g, '.*') + '$')
    : null;

  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    if (pattern && !pattern.test(entry.name.replace('.sol', ''))) continue;

    const subdir = join(dir, entry.name);
    for (const file of readdirSync(subdir)) {
      if (file.endsWith('.json') && !file.includes('.dbg.')) {
        results.push(join(subdir, file));
      }
    }
  }
  return results.sort();
}

// ─── Scan Text Output ────────────────────────────────────────────────────────

const SEP = '─'.repeat(55);
const DSEP = '═'.repeat(55);

function verdictIcon(verdict: string): string {
  if (verdict === 'safe') return '✅ SAFE';
  if (verdict === 'conditional') return '⚠  CONDITIONAL';
  return '✗  UNSAFE';
}

function formatReport(result: ScanResult, name?: string): string {
  const lines: string[] = [];
  const p = (s: string) => lines.push(s);

  p(`\n${DSEP}`);
  p(`  EIP-8130 Verifier Scanner${name ? ` — ${name}` : ''}`);
  p(DSEP);

  if (result.is7702Delegation) {
    p(`\n── EIP-7702 Delegation ${SEP.slice(23)}`);
    p(`  ✗ Bytecode is an EIP-7702 delegation designator`);
    p(`  Target:       ${result.delegationTarget}`);
    p(`  This is not verifier bytecode — it delegates execution to another address.`);
    p(`\n${DSEP}`);
    p(`  VERDICT: ✗  UNSAFE`);
    p(DSEP);
    for (const reason of result.verdictReasons) p(`  ✗ ${reason}`);
    p(DSEP);
    return lines.join('\n');
  }

  p(`\n── Spec Limits ${SEP.slice(15)}`);
  const sizeIcon = result.exceedsSizeLimit ? '✗' : '✓';
  p(`  Bytecode:     ${result.bytecodeSize.toLocaleString()}B / ${MAX_BYTECODE_SIZE.toLocaleString()}B ${sizeIcon}`);
  const gasIcon = result.exceedsGasBudget ? '✗' : '✓';
  p(`  Gas estimate: ~${result.maxGasEstimate.toLocaleString()} / ${GAS_BUDGET.toLocaleString()} ${gasIcon}`);
  p(`  Hard kill:    ${HARD_KILL_MS}ms wall-clock (runtime enforced)`);

  p(`\n── Bytecode ${SEP.slice(12)}`);
  p(`  Total:        ${result.bytecodeSize} bytes`);
  if (result.metadataSize > 0) {
    p(`  Code:         ${result.codeSize} bytes`);
    p(`  Non-code:     ${result.metadataSize} bytes (data section + Solidity CBOR — excluded from scan)`);
  }
  p(`  Instructions: ${result.instructionCount} (${result.uniqueOpcodes} unique opcodes)`);

  p(`\n── Forbidden Opcodes ${SEP.slice(21)}`);
  if (result.forbiddenInCode.length === 0) {
    p(`  In code:      NONE ✓`);
  } else {
    p(`  In code:      ${result.forbiddenInCode.length} ✗`);
    const grouped = new Map<string, { offsets: number[]; reason: string }>();
    for (const h of result.forbiddenInCode) {
      const existing = grouped.get(h.name);
      if (existing) { existing.offsets.push(h.offset); }
      else { grouped.set(h.name, { offsets: [h.offset], reason: h.reason }); }
    }
    for (const [name, { offsets, reason }] of grouped) {
      const locs = offsets.map(o => `0x${o.toString(16).padStart(4, '0')}`).join(', ');
      p(`    ✗ ${name} (${reason}) at ${locs}`);
    }
  }
  const metaForbidden = result.forbidden.filter(h => h.inMetadata);
  if (metaForbidden.length > 0) {
    p(`  In metadata:  ${metaForbidden.length} (ignored — unreachable data)`);
  }

  if (result.staticcalls.length > 0) {
    p(`\n── STATICCALL Targets ${SEP.slice(22)}`);
    p(`  Count:        ${result.staticcalls.length}`);
    for (const sc of result.staticcalls) {
      if (sc.resolved && sc.precompileName) {
        p(`    ✓ 0x${sc.offset.toString(16).padStart(4, '0')} → ${sc.precompileName} (0x${sc.target!.toString(16)})`);
      } else if (sc.resolved) {
        p(`    ✗ 0x${sc.offset.toString(16).padStart(4, '0')} → 0x${sc.target!.toString(16)} (not a precompile)`);
      } else {
        p(`    ⚠ 0x${sc.offset.toString(16).padStart(4, '0')} → unresolved (runtime check required)`);
      }
    }
    if (result.allStaticCallsSafe) {
      p(`  All targets are allowlisted precompiles ✓`);
    }
  }

  p(`\n── DoS Assessment ${SEP.slice(19)}`);
  if (!result.hasLoops && !result.hasDynamicJumps) {
    p(`  Terminates:   YES (provably — no loops, no dynamic jumps) ✓`);
  } else {
    if (result.hasLoops) {
      p(`  Loops:        ${result.backEdges.length} back-edge(s) detected`);
      for (const [src, dst] of result.backEdges) {
        p(`    0x${src.toString(16).padStart(4, '0')} → 0x${dst.toString(16).padStart(4, '0')}`);
      }
    }
    if (result.hasDynamicJumps) {
      p(`  Dynamic jumps: ${result.dynamicJumpCount}`);
    }
    p(`  Terminates:   bounded by gas provided at call time`);
  }
  p(`  Gas estimate: ~${result.maxGasEstimate.toLocaleString()} (sum of base opcode costs)`);

  p(`\n${DSEP}`);
  p(`  VERDICT: ${verdictIcon(result.verdict)}`);
  p(DSEP);
  for (const reason of result.verdictReasons) {
    const isGood = reason.includes('no forbidden') || reason.includes('precompile') ||
      reason.includes('provably') || reason.includes('pure computation') ||
      reason.includes('within');
    const isInfo = reason.includes('bounded by');
    const icon = isGood ? '✓' : isInfo ? '·' : '✗';
    p(`  ${icon} ${reason}`);
  }
  p(DSEP);

  return lines.join('\n');
}

function formatJson(result: ScanResult): string {
  return JSON.stringify({
    bytecodeSize: result.bytecodeSize,
    is7702Delegation: result.is7702Delegation,
    delegationTarget: result.delegationTarget,
    codeSize: result.codeSize,
    metadataSize: result.metadataSize,
    specLimits: {
      maxBytecodeSize: MAX_BYTECODE_SIZE,
      gasBudget: GAS_BUDGET,
      hardKillMs: HARD_KILL_MS,
      exceedsSizeLimit: result.exceedsSizeLimit,
      exceedsGasBudget: result.exceedsGasBudget,
    },
    safety: {
      forbiddenInCode: result.forbiddenInCode.map(h => ({
        offset: h.offset, name: h.name, reason: h.reason,
      })),
      forbiddenInMetadata: result.forbidden.filter(h => h.inMetadata).length,
    },
    staticcalls: result.staticcalls.map(s => ({
      offset: s.offset,
      target: s.target !== null ? `0x${s.target.toString(16)}` : null,
      precompile: s.precompileName,
      resolved: s.resolved,
    })),
    dos: {
      hasLoops: result.hasLoops,
      backEdges: result.backEdges,
      hasDynamicJumps: result.hasDynamicJumps,
      dynamicJumpCount: result.dynamicJumpCount,
      maxGasEstimate: result.maxGasEstimate,
    },
    verdict: result.verdict,
    verdictReasons: result.verdictReasons,
  }, null, 2);
}

// ─── Execute Output ──────────────────────────────────────────────────────────

function formatExecuteReport(result: ExecuteResult, name?: string): string {
  const lines: string[] = [];
  const p = (s: string) => lines.push(s);

  p(`\n${DSEP}`);
  p(`  EIP-8130 Sandbox Execution${name ? ` — ${name}` : ''}`);
  p(DSEP);

  p(`\n── Execution Result ${SEP.slice(20)}`);
  p(`  Status:       ${result.success ? '✓ SUCCESS' : '✗ REVERTED'}`);
  p(`  Gas used:     ${result.gasUsed.toLocaleString()}`);
  if (result.ownerId) {
    p(`  Owner ID:     ${result.ownerId}`);
  } else if (result.success) {
    p(`  Owner ID:     bytes32(0) — invalid signature`);
  }
  if (result.error) {
    p(`  Error:        ${result.error}`);
  }

  if (result.forbiddenOpcodeHits.length > 0) {
    p(`\n── Sandbox Violations ${SEP.slice(22)}`);
    const grouped = new Map<string, number[]>();
    for (const hit of result.forbiddenOpcodeHits) {
      const existing = grouped.get(hit.opcode);
      if (existing) existing.push(hit.pc);
      else grouped.set(hit.opcode, [hit.pc]);
    }
    for (const [opcode, pcs] of grouped) {
      const locs = pcs.map(pc => `0x${pc.toString(16).padStart(4, '0')}`).join(', ');
      p(`    ✗ ${opcode} at PC ${locs}`);
    }
  }

  if (result.staticcallTargets.length > 0) {
    p(`\n── STATICCALL Targets ${SEP.slice(22)}`);
    for (const sc of result.staticcallTargets) {
      const icon = sc.isPrecompile ? '✓' : '✗';
      p(`    ${icon} PC 0x${sc.pc.toString(16).padStart(4, '0')} → 0x${sc.address.toString(16)} ${sc.isPrecompile ? '(precompile)' : '(NOT a precompile)'}`);
    }
  }

  p(`\n${DSEP}`);
  p(`  SANDBOX: ${result.sandboxSafe ? '✅ SAFE' : '✗  UNSAFE'}`);
  p(DSEP);

  return lines.join('\n');
}

function formatExecuteJson(result: ExecuteResult): string {
  return JSON.stringify({
    gasUsed: Number(result.gasUsed),
    success: result.success,
    ownerId: result.ownerId,
    error: result.error,
    sandboxSafe: result.sandboxSafe,
    forbiddenOpcodeHits: result.forbiddenOpcodeHits,
    staticcallTargets: result.staticcallTargets,
  }, null, 2);
}

// ─── Batch Mode ──────────────────────────────────────────────────────────────

interface BatchRow {
  contract: string;
  size: number;
  gas: number;
  forbiddenInCode: number;
  staticcalls: number;
  loops: boolean;
  verdict: string;
}

function runBatch(dir: string, filter?: string, outputDir?: string, jsonMode?: boolean): void {
  const artifacts = findArtifacts(dir, filter);
  if (artifacts.length === 0) {
    console.error(`No artifacts found in ${dir}${filter ? ` (filter: ${filter})` : ''}`);
    process.exit(1);
  }

  console.log(`\n  Scanning ${artifacts.length} artifact(s) in ${dir}${filter ? ` (filter: ${filter})` : ''}...\n`);
  console.log(`  Spec limits: ${MAX_BYTECODE_SIZE.toLocaleString()}B bytecode, ${GAS_BUDGET.toLocaleString()} gas, ${HARD_KILL_MS}ms hard kill\n`);

  if (outputDir) mkdirSync(outputDir, { recursive: true });

  const rows: BatchRow[] = [];
  const summaryData: object[] = [];

  for (const path of artifacts) {
    const { name, bytecode } = loadArtifact(path);
    const result = scan(bytecode);

    rows.push({
      contract: name,
      size: bytecode.length,
      gas: result.maxGasEstimate,
      forbiddenInCode: result.forbiddenInCode.length,
      staticcalls: result.staticcalls.length,
      loops: result.hasLoops,
      verdict: result.verdict,
    });

    if (outputDir) {
      writeFileSync(join(outputDir, `${name}.txt`), formatReport(result, name));
      writeFileSync(join(outputDir, `${name}.json`), formatJson(result));
    }

    summaryData.push({ contract: name, ...JSON.parse(formatJson(result)) });
  }

  const W = 100;
  console.log(`${'═'.repeat(W)}`);
  console.log(
    `  ${'Contract'.padEnd(25)} ${'Size'.padStart(7)} ${'Gas'.padStart(8)} ` +
    `${'Banned'.padStart(6)} ${'Calls'.padStart(5)} ${'Loops'.padStart(5)} ${'Verdict'.padStart(12)}`
  );
  console.log(`${'─'.repeat(W)}`);

  for (const row of rows) {
    const v = row.verdict === 'safe' ? '✅ safe' :
      row.verdict === 'conditional' ? '⚠  cond' : '✗  unsafe';
    const sizeStr = row.size > MAX_BYTECODE_SIZE ? `${row.size}B!` : `${row.size}B`;
    const gasStr = row.gas > GAS_BUDGET ? `${row.gas.toLocaleString()}!` : row.gas.toLocaleString();
    console.log(
      `  ${row.contract.padEnd(25)} ${sizeStr.padStart(7)} ${gasStr.padStart(8)} ` +
      `${String(row.forbiddenInCode).padStart(6)} ${String(row.staticcalls).padStart(5)} ` +
      `${(row.loops ? 'yes' : 'no').padStart(5)} ${v.padStart(12)}`
    );
  }
  console.log(`${'═'.repeat(W)}`);

  if (outputDir) {
    const summaryPath = join(outputDir, 'SUMMARY.json');
    writeFileSync(summaryPath, JSON.stringify(summaryData, null, 2));
    console.log(`\n  Reports: ${outputDir}/`);
    console.log(`  Summary: ${summaryPath}\n`);
  }
}

// ─── Execute Mode ────────────────────────────────────────────────────────────

async function runExecute(args: Args): Promise<void> {
  let bytecode: Uint8Array;
  let name: string | undefined;

  if (args.artifact) {
    const loaded = loadArtifact(args.artifact);
    bytecode = loaded.bytecode;
    name = loaded.name;
  } else if (args.hex) {
    bytecode = hexToBytes(args.hex);
  } else if (args.file) {
    const raw = readFileSync(resolve(args.file), 'utf-8').trim();
    bytecode = hexToBytes(raw);
    name = basename(args.file);
  } else {
    console.error('--execute requires --artifact, --hex, or --file');
    process.exit(1);
    return;
  }

  const gasLimit = args.gasLimit ? BigInt(args.gasLimit) : undefined;

  let result: ExecuteResult;
  if (args.calldata) {
    result = await execute({
      bytecode,
      calldata: hexToBytes(args.calldata),
      gasLimit,
    });
  } else {
    result = await execute({
      bytecode,
      account: args.account ? hexToBytes(args.account) : undefined,
      hash: args.hash ? hexToBytes(args.hash) : undefined,
      data: args.data ? hexToBytes(args.data) : undefined,
      gasLimit,
    });
  }

  if (args.json) {
    console.log(formatExecuteJson(result));
  } else {
    console.log(formatExecuteReport(result, name));
  }

  process.exit(result.success ? 0 : 1);
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = parseArgs();

  if (args.execute) {
    await runExecute(args);
    return;
  }

  if (args.batch) {
    runBatch(args.batch, args.filter, args.output, args.json);
    return;
  }

  let bytecode: Uint8Array;
  let name: string | undefined;

  if (args.hex) {
    bytecode = hexToBytes(args.hex);
  } else if (args.file) {
    const raw = readFileSync(resolve(args.file), 'utf-8').trim();
    bytecode = hexToBytes(raw);
    name = basename(args.file);
  } else if (args.artifact) {
    const loaded = loadArtifact(args.artifact);
    bytecode = loaded.bytecode;
    name = loaded.name;
  } else {
    printUsage();
    process.exit(1);
    return;
  }

  const result = scan(bytecode);

  if (args.json) {
    console.log(formatJson(result));
  } else {
    console.log(formatReport(result, name));
  }

  if (args.output) {
    const ext = args.json ? '.json' : '.txt';
    writeFileSync(args.output + ext, args.json ? formatJson(result) : formatReport(result, name));
  }

  process.exit(result.verdict === 'safe' ? 0 : result.verdict === 'conditional' ? 0 : 1);
}

main();
