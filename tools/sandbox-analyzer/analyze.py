#!/usr/bin/env python3
"""EIP-8130 Sandbox Verifier Bytecode Analyzer.

Performs static analysis on EVM bytecode to determine if it qualifies as a
safe EIP-8130 sandbox verifier. Checks header format, opcode safety,
STATICCALL targets, control flow, gas estimation, and termination properties.

Usage:
    python analyze.py --hex 600956813000640005b...
    python analyze.py --file bytecode.hex
    python analyze.py --artifact out/BLSVerifier.sol/BLSVerifier.json
    python analyze.py --hex 600956... --disasm
    python analyze.py --hex 600956... --json
"""

import argparse
import json
import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from opcodes import (
    OPCODES,
    PRECOMPILE_BASE_GAS,
    PRECOMPILES,
    OpcodeInfo,
    SandboxStatus,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Data Structures
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class Instruction:
    offset: int
    opcode: OpcodeInfo
    immediate: bytes = b""

    @property
    def size(self) -> int:
        return 1 + len(self.immediate)

    @property
    def value(self) -> int:
        if not self.immediate:
            return 0
        return int.from_bytes(self.immediate, "big")

    def __repr__(self) -> str:
        if self.immediate:
            return f"{self.offset:04x}: {self.opcode.name} 0x{self.immediate.hex()}"
        return f"{self.offset:04x}: {self.opcode.name}"


@dataclass
class HeaderInfo:
    valid: bool
    format: str  # "spec", "legacy_v0" (old 10-byte with gas_limit), "none"
    magic_valid: bool
    gas_limit: int       # legacy only; 0 for current spec
    gas_limit_raw: int   # legacy only
    version: int
    header_size: int
    bytecode_size: int
    errors: list[str] = field(default_factory=list)


@dataclass
class BasicBlock:
    start: int
    instructions: list[Instruction] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)

    @property
    def end(self) -> int:
        if not self.instructions:
            return self.start
        last = self.instructions[-1]
        return last.offset + last.size

    @property
    def gas_cost(self) -> int:
        return sum(i.opcode.base_gas for i in self.instructions)

    @property
    def has_dynamic_gas(self) -> bool:
        return any(i.opcode.dynamic_gas for i in self.instructions)


@dataclass
class StaticCallTarget:
    offset: int
    target: Optional[int]
    is_precompile: bool
    precompile_name: Optional[str]
    precompile_gas: Optional[int]


# ═══════════════════════════════════════════════════════════════════════════════
# Disassembler
# ═══════════════════════════════════════════════════════════════════════════════


def disassemble(bytecode: bytes, start: int = 0) -> list[Instruction]:
    """Disassemble EVM bytecode into a list of instructions."""
    instructions = []
    i = start
    while i < len(bytecode):
        byte = bytecode[i]
        opinfo = OPCODES.get(byte)
        if opinfo is None:
            opinfo = OpcodeInfo(
                byte, f"UNKNOWN_0x{byte:02X}", 0, 0, 0, 0,
                SandboxStatus.FORBIDDEN, "unknown",
            )

        imm = bytecode[i + 1 : i + 1 + opinfo.immediate_size]
        instructions.append(Instruction(i, opinfo, imm))
        i += 1 + opinfo.immediate_size

    return instructions


# ═══════════════════════════════════════════════════════════════════════════════
# Header Parsing
# ═══════════════════════════════════════════════════════════════════════════════


def parse_header(bytecode: bytes) -> HeaderInfo:
    """Parse and validate the EIP-8130 sandbox verifier header."""
    none = HeaderInfo(False, "none", False, 0, 0, 0, 0, len(bytecode))

    if len(bytecode) < 7:
        none.errors.append("Bytecode too short for any 8130 header")
        return none

    if bytecode[0] != 0x60 or bytecode[2] != 0x56:
        none.errors.append("No PUSH1/JUMP preamble")
        return none

    if bytecode[3:5] != b"\x81\x30":
        none.errors.append("Missing 8130 magic at bytes 3-4")
        return none

    jump_offset = bytecode[1]
    errors: list[str] = []

    # Current spec format: 7-byte header (no gas_limit)
    #   Byte 0:   PUSH1 0x06
    #   Byte 2:   JUMP
    #   Byte 3-4: magic 0x8130
    #   Byte 5:   version
    #   Byte 6:   JUMPDEST
    if jump_offset == 0x06:
        version = bytecode[5]
        if bytecode[6] != 0x5B:
            errors.append(f"Expected JUMPDEST at byte 6, got 0x{bytecode[6]:02X}")
        return HeaderInfo(
            valid=len(errors) == 0, format="spec", magic_valid=True,
            gas_limit=0, gas_limit_raw=0, version=version,
            header_size=7, bytecode_size=len(bytecode), errors=errors,
        )

    # Legacy format: 10-byte header with 3-byte gas_limit (removed from spec —
    # gas_limit in bytecode breaks on repricing)
    if jump_offset == 0x09:
        if len(bytecode) < 10:
            return HeaderInfo(
                False, "none", True, 0, 0, 0, 0, len(bytecode),
                ["Bytecode too short for legacy header (need 10 bytes)"],
            )
        raw = (bytecode[5] << 16) | (bytecode[6] << 8) | bytecode[7]
        gas_limit = raw * 1000
        version = bytecode[8]
        if bytecode[9] != 0x5B:
            errors.append(f"Expected JUMPDEST at byte 9, got 0x{bytecode[9]:02X}")
        errors.append("Legacy 10-byte header with gas_limit — removed from spec (breaks on repricing)")
        return HeaderInfo(
            valid=False, format="legacy_v0", magic_valid=True,
            gas_limit=gas_limit, gas_limit_raw=raw, version=version,
            header_size=10, bytecode_size=len(bytecode), errors=errors,
        )

    errors.append(
        f"Unknown jump offset 0x{jump_offset:02X} "
        "(expected 0x06 for spec header)"
    )
    return HeaderInfo(False, "none", True, 0, 0, 0, 0, len(bytecode), errors)


# ═══════════════════════════════════════════════════════════════════════════════
# Control Flow Graph
# ═══════════════════════════════════════════════════════════════════════════════

TERMINATORS = frozenset({"STOP", "RETURN", "REVERT", "INVALID", "JUMP", "SELFDESTRUCT"})
EXITS = frozenset({"STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT"})


def build_cfg(instructions: list[Instruction]) -> dict[int, BasicBlock]:
    """Build a control flow graph from disassembled instructions."""
    if not instructions:
        return {}

    jumpdests = {i.offset for i in instructions if i.opcode.name == "JUMPDEST"}

    # Identify basic block boundaries
    block_starts: set[int] = {instructions[0].offset}
    for inst in instructions:
        name = inst.opcode.name
        if name in TERMINATORS or name == "JUMPI":
            nxt = inst.offset + inst.size
            if nxt <= instructions[-1].offset:
                block_starts.add(nxt)
        if name == "JUMPDEST":
            block_starts.add(inst.offset)

    sorted_starts = sorted(block_starts)
    start_set = set(sorted_starts)

    # Partition instructions into blocks
    blocks: dict[int, BasicBlock] = {}
    for idx, start in enumerate(sorted_starts):
        end = sorted_starts[idx + 1] if idx + 1 < len(sorted_starts) else len(instructions[0].immediate) + instructions[-1].offset + instructions[-1].size
        block = BasicBlock(start=start)
        for inst in instructions:
            if inst.offset >= start and (idx + 1 >= len(sorted_starts) or inst.offset < sorted_starts[idx + 1]):
                block.instructions.append(inst)
        if block.instructions:
            blocks[start] = block

    # Resolve edges
    for block in blocks.values():
        if not block.instructions:
            continue
        last = block.instructions[-1]
        name = last.opcode.name

        if name == "JUMP":
            target = _resolve_jump_target(block)
            if target is not None and target in jumpdests:
                block.successors.append(target)
        elif name == "JUMPI":
            target = _resolve_jump_target(block)
            if target is not None and target in jumpdests:
                block.successors.append(target)
            fallthrough = last.offset + last.size
            if fallthrough in blocks:
                block.successors.append(fallthrough)
        elif name not in EXITS:
            fallthrough = last.offset + last.size
            if fallthrough in blocks:
                block.successors.append(fallthrough)

    return blocks


def _resolve_jump_target(block: BasicBlock) -> Optional[int]:
    """Try to resolve a static jump target by inspecting the preceding instruction."""
    if len(block.instructions) < 2:
        return None
    prev = block.instructions[-2]
    name = prev.opcode.name
    if name.startswith("PUSH") and name != "PUSH0":
        return prev.value
    if name == "PUSH0":
        return 0
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# Safety Analysis
# ═══════════════════════════════════════════════════════════════════════════════


def analyze_safety(instructions: list[Instruction]) -> dict:
    """Check all opcodes against the sandbox allowlist."""
    forbidden: list[Instruction] = []
    restricted: list[Instruction] = []
    opcode_counts: dict[str, int] = defaultdict(int)
    dynamic_gas: list[Instruction] = []

    for inst in instructions:
        opcode_counts[inst.opcode.name] += 1
        if inst.opcode.sandbox == SandboxStatus.FORBIDDEN:
            forbidden.append(inst)
        elif inst.opcode.sandbox == SandboxStatus.RESTRICTED:
            restricted.append(inst)
        if inst.opcode.dynamic_gas:
            dynamic_gas.append(inst)

    return {
        "forbidden": forbidden,
        "restricted": restricted,
        "opcode_counts": dict(opcode_counts),
        "dynamic_gas": dynamic_gas,
        "total_instructions": len(instructions),
        "unique_opcodes": len(opcode_counts),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# STATICCALL Target Analysis
# ═══════════════════════════════════════════════════════════════════════════════


def analyze_staticcall_targets(
    instructions: list[Instruction],
    blocks: dict[int, BasicBlock],
) -> list[StaticCallTarget]:
    """For each STATICCALL, determine the target address via stack simulation.

    Uses intra-block simulation first; falls back to cross-block predecessor
    tracing and a bytecode-wide heuristic scan for precompile address PUSHes.
    """
    # Build reverse map: block_start → set of predecessor block starts
    predecessors: dict[int, list[int]] = defaultdict(list)
    for blk in blocks.values():
        for succ in blk.successors:
            predecessors[succ].append(blk.start)

    results = []
    for block in blocks.values():
        for idx, inst in enumerate(block.instructions):
            if inst.opcode.name != "STATICCALL":
                continue

            # Try 1: intra-block stack simulation
            target = _simulate_stack_for_target(block.instructions[:idx])

            # Try 2: trace through predecessor blocks (up to 2 hops)
            if target is None and block.start in predecessors:
                for pred_start in predecessors[block.start]:
                    pred = blocks.get(pred_start)
                    if pred is None:
                        continue
                    combined = pred.instructions + block.instructions[:idx]
                    target = _simulate_stack_for_target(combined)
                    if target is not None:
                        break
                    # 2nd hop
                    if target is None and pred_start in predecessors:
                        for gp_start in predecessors[pred_start]:
                            gp = blocks.get(gp_start)
                            if gp is None:
                                continue
                            combined2 = gp.instructions + combined
                            target = _simulate_stack_for_target(combined2)
                            if target is not None:
                                break
                    if target is not None:
                        break

            is_pre = target is not None and target in PRECOMPILES
            results.append(StaticCallTarget(
                offset=inst.offset,
                target=target,
                is_precompile=is_pre,
                precompile_name=PRECOMPILES.get(target) if target is not None else None,
                precompile_gas=PRECOMPILE_BASE_GAS.get(target) if target is not None else None,
            ))
    return results


def _simulate_stack_for_target(instructions: list[Instruction]) -> Optional[int]:
    """Forward-simulate the stack within a basic block to find STATICCALL's addr arg.

    STATICCALL consumes (top→bottom): gas, addr, argsOffset, argsLength, retOffset, retLength.
    We need stack[-2] (the address, second from top) just before the STATICCALL executes.
    """
    stack: list[Optional[int]] = []

    for inst in instructions:
        name = inst.opcode.name

        if name.startswith("PUSH"):
            stack.append(inst.value if name != "PUSH0" else 0)
            continue

        if name in ("GAS", "RETURNDATASIZE", "CALLDATASIZE", "MSIZE", "PC"):
            stack.append(None)
            continue

        if name.startswith("DUP"):
            n = int(name[3:])
            if len(stack) >= n:
                stack.append(stack[-n])
            else:
                stack.append(None)
            continue

        if name.startswith("SWAP"):
            n = int(name[4:])
            if len(stack) > n:
                stack[-1], stack[-(n + 1)] = stack[-(n + 1)], stack[-1]
            continue

        # Generic: pop inputs, push unknown outputs
        si = inst.opcode.stack_in
        so = inst.opcode.stack_out
        for _ in range(min(si, len(stack))):
            stack.pop()
        for _ in range(so):
            stack.append(None)

    # addr is at stack[-2] (second from top, after gas)
    if len(stack) >= 2:
        return stack[-2]
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# Termination Analysis
# ═══════════════════════════════════════════════════════════════════════════════


def analyze_termination(blocks: dict[int, BasicBlock], entry: int) -> dict:
    """Detect loops via back-edge detection in DFS traversal of the CFG."""
    visited: set[int] = set()
    on_stack: set[int] = set()
    back_edges: list[tuple[int, int]] = []
    topo_order: list[int] = []

    def dfs(offset: int) -> None:
        if offset not in blocks:
            return
        visited.add(offset)
        on_stack.add(offset)
        for succ in blocks[offset].successors:
            if succ in on_stack:
                back_edges.append((offset, succ))
            elif succ not in visited:
                dfs(succ)
        on_stack.discard(offset)
        topo_order.append(offset)

    sys.setrecursionlimit(10000)
    if entry in blocks:
        dfs(entry)

    reachable = visited
    unreachable = set(blocks.keys()) - reachable

    exits: dict[str, int] = defaultdict(int)
    for off in reachable:
        block = blocks[off]
        if block.instructions:
            last = block.instructions[-1]
            if last.opcode.name in EXITS:
                exits[last.opcode.name] += 1

    dynamic_jumps = []
    for off in reachable:
        block = blocks[off]
        if block.instructions:
            last = block.instructions[-1]
            if last.opcode.name in ("JUMP", "JUMPI") and not block.successors:
                dynamic_jumps.append(last.offset)

    return {
        "has_loops": len(back_edges) > 0,
        "back_edges": back_edges,
        "loop_count": len(back_edges),
        "provably_terminates": len(back_edges) == 0 and len(dynamic_jumps) == 0,
        "reachable_blocks": len(reachable),
        "unreachable_blocks": len(unreachable),
        "unreachable_offsets": sorted(unreachable),
        "exit_points": dict(exits),
        "dynamic_jumps": dynamic_jumps,
        "topo_order": list(reversed(topo_order)),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Gas Estimation
# ═══════════════════════════════════════════════════════════════════════════════


def estimate_gas(
    blocks: dict[int, BasicBlock],
    entry: int,
    termination: dict,
    staticcall_targets: list[StaticCallTarget],
) -> dict:
    """Estimate gas via longest/shortest-path analysis on the CFG.

    For loop-free graphs: exact min/max static gas costs.
    For graphs with loops: sum of all reachable block costs as upper bound.
    """
    if not blocks or entry not in blocks:
        return {"min_path": 0, "max_path": 0, "exact": True, "dynamic_sources": []}

    if termination["has_loops"]:
        total = sum(b.gas_cost for off, b in blocks.items()
                     if off in set(termination["topo_order"]))
        return {
            "min_path": 0,
            "max_path": total,
            "exact": False,
            "reason": "Contains loops — bounded only by gas provided at call time",
        }

    # DAG: compute exact min/max via DFS with memoization
    max_memo: dict[int, int] = {}
    min_memo: dict[int, int] = {}

    def max_dp(offset: int) -> int:
        if offset in max_memo:
            return max_memo[offset]
        block = blocks.get(offset)
        if block is None:
            return 0
        cost = block.gas_cost
        valid_succs = [s for s in block.successors if s in blocks]
        if not valid_succs:
            max_memo[offset] = cost
            return cost
        best = max(max_dp(s) for s in valid_succs)
        result = cost + best
        max_memo[offset] = result
        return result

    def min_dp(offset: int) -> int:
        if offset in min_memo:
            return min_memo[offset]
        block = blocks.get(offset)
        if block is None:
            return 0
        cost = block.gas_cost
        valid_succs = [s for s in block.successors if s in blocks]
        if not valid_succs:
            min_memo[offset] = cost
            return cost
        best = min(min_dp(s) for s in valid_succs)
        result = cost + best
        min_memo[offset] = result
        return result

    max_gas = max_dp(entry)
    min_gas = min_dp(entry)

    # Collect STATICCALL precompile gas costs along paths
    precompile_costs = []
    for sc in staticcall_targets:
        if sc.precompile_gas:
            precompile_costs.append((sc.precompile_name, sc.precompile_gas))

    # Collect dynamic gas sources
    dynamic_sources = []
    for block in blocks.values():
        for inst in block.instructions:
            if inst.opcode.dynamic_gas:
                dynamic_sources.append(inst.opcode.name)

    return {
        "min_path": min_gas,
        "max_path": max_gas,
        "exact": True,
        "reason": "Loop-free — exact path analysis (static gas only)",
        "precompile_costs": precompile_costs,
        "dynamic_sources": sorted(set(dynamic_sources)),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Stack Depth Analysis
# ═══════════════════════════════════════════════════════════════════════════════


def analyze_stack(
    blocks: dict[int, BasicBlock],
    entry: int,
    termination: dict,
) -> dict:
    """Propagate stack depths through the CFG to find max depth and underflows."""
    if not blocks or entry not in blocks:
        return {"max_depth": 0, "underflows": [], "overflow": False}

    # entry_depth[block_offset] = stack depth at block entry
    entry_depth: dict[int, int] = {entry: 0}
    max_depth = 0
    underflows: list[tuple[int, str, int]] = []
    worklist = deque([entry])
    visited: set[int] = set()

    while worklist:
        off = worklist.popleft()
        if off in visited:
            continue
        visited.add(off)

        block = blocks.get(off)
        if block is None:
            continue

        depth = entry_depth.get(off, 0)
        for inst in block.instructions:
            name = inst.opcode.name

            min_req = inst.opcode.min_stack_depth
            if depth < min_req:
                underflows.append((inst.offset, name, depth - min_req))

            depth -= inst.opcode.stack_in
            if depth < 0 and depth + inst.opcode.stack_in >= min_req:
                underflows.append((inst.offset, name, depth))
            depth = max(depth, 0)
            depth += inst.opcode.stack_out
            max_depth = max(max_depth, depth)

        for succ in block.successors:
            if succ not in entry_depth or depth > entry_depth[succ]:
                entry_depth[succ] = depth
            if succ not in visited:
                worklist.append(succ)

    return {
        "max_depth": max_depth,
        "underflows": underflows,
        "overflow": max_depth > 1024,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Wrapper Detection
# ═══════════════════════════════════════════════════════════════════════════════


def detect_wrapper(bytecode: bytes, header: HeaderInfo) -> Optional[dict]:
    """Detect if bytecode is a SandboxLib STATICCALL wrapper and extract the target.

    SandboxLib wrappers use the spec 7-byte header + a 45-byte STATICCALL forwarder
    (52 bytes total). The PUSH20 at byte 16 embeds the wrapped verifier address.
    """
    if header.format != "spec" or len(bytecode) < 37:
        return None

    # SandboxLib wrapper: byte 16 should be PUSH20 (0x73)
    if bytecode[16] != 0x73:
        return None

    addr_bytes = bytecode[17:37]
    addr = int.from_bytes(addr_bytes, "big")
    return {
        "is_wrapper": True,
        "wrapped_verifier": f"0x{addr:040x}",
        "wrapper_size": len(bytecode),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Report Formatting
# ═══════════════════════════════════════════════════════════════════════════════

_SEP = "─" * 60
_DSEP = "═" * 60


def _bar(count: int, total: int, width: int = 20) -> str:
    if total == 0:
        return ""
    filled = int(count / total * width)
    return "█" * filled + "░" * (width - filled)


def format_report(
    bytecode: bytes,
    header: HeaderInfo,
    safety: dict,
    staticcall_targets: list[StaticCallTarget],
    cfg_blocks: dict[int, BasicBlock],
    termination: dict,
    gas: dict,
    stack: dict,
    wrapper: Optional[dict],
    show_disasm: bool = False,
    code_instructions: list[Instruction] | None = None,
    all_instructions: list[Instruction] | None = None,
) -> str:
    lines: list[str] = []
    p = lines.append

    p(f"\n{_DSEP}")
    p("  EIP-8130 Sandbox Verifier Bytecode Analyzer")
    p(_DSEP)

    # ── Header ──
    p(f"\n── Header {_SEP[10:]}")
    if header.format == "spec":
        p(f"  Format:      8130 (7-byte header)")
        p(f"  Magic:       8130 ✓")
        p(f"  Version:     {header.version}")
        p(f"  Total Size:  {header.bytecode_size} bytes ({header.bytecode_size - header.header_size} after header)")
        if wrapper:
            p(f"  Wrapper:     SandboxLib STATICCALL proxy → {wrapper['wrapped_verifier']}")
    elif header.format == "legacy_v0":
        p(f"  Format:      Legacy (10-byte header with gas_limit)")
        p(f"  Magic:       8130 ✓")
        p(f"  Gas Limit:   {header.gas_limit:,} gas (raw: {header.gas_limit_raw} × 1,000)")
        p(f"  Version:     {header.version}")
        p(f"  Total Size:  {header.bytecode_size} bytes ({header.bytecode_size - header.header_size} after header)")
        p(f"  ⚠ Legacy format — gas_limit removed from spec (breaks on repricing)")
    else:
        p(f"  Format:      None (no valid 8130 header)")
        p(f"  Total Size:  {header.bytecode_size} bytes")
        for err in header.errors:
            p(f"  ✗ {err}")

    if header.errors and header.format != "none":
        for err in header.errors:
            p(f"  ⚠ {err}")

    # ── Disassembly ──
    if show_disasm and all_instructions:
        p(f"\n── Disassembly {_SEP[15:]}")
        if header.header_size > 0:
            p("  HEADER:")
            for inst in all_instructions:
                if inst.offset >= header.header_size:
                    break
                if inst.immediate:
                    p(f"    {inst.offset:04X}: {inst.opcode.name:<16s} 0x{inst.immediate.hex()}")
                else:
                    p(f"    {inst.offset:04X}: {inst.opcode.name}")
            p("  CODE:")
        for inst in (code_instructions or []):
            if inst.immediate:
                p(f"    {inst.offset:04X}: {inst.opcode.name:<16s} 0x{inst.immediate.hex()}")
            else:
                p(f"    {inst.offset:04X}: {inst.opcode.name}")

    # ── Opcode Safety ──
    p(f"\n── Opcode Safety {_SEP[17:]}")
    p(f"  Instructions:  {safety['total_instructions']} total, {safety['unique_opcodes']} unique opcodes")

    if safety["forbidden"]:
        p(f"  Forbidden:     {len(safety['forbidden'])} ✗ UNSAFE")
        seen: set[str] = set()
        for inst in safety["forbidden"]:
            key = inst.opcode.name
            if key not in seen:
                offsets = [f"0x{i.offset:04X}" for i in safety["forbidden"] if i.opcode.name == key]
                p(f"    ✗ {key} ({inst.opcode.category}) at {', '.join(offsets[:5])}"
                  + (f" ... +{len(offsets)-5} more" if len(offsets) > 5 else ""))
                seen.add(key)
    else:
        p(f"  Forbidden:     None ✓")

    if safety["restricted"]:
        p(f"  STATICCALL:    {len(safety['restricted'])} instance(s) (target check required)")

    # Opcode usage breakdown (top 10)
    sorted_ops = sorted(safety["opcode_counts"].items(), key=lambda x: -x[1])
    total = safety["total_instructions"]
    if sorted_ops:
        p(f"\n  Top opcodes:")
        for name, count in sorted_ops[:12]:
            pct = count / total * 100
            p(f"    {name:<16s} {count:>4d}  {_bar(count, total, 15)} {pct:5.1f}%")

    # ── STATICCALL Targets ──
    if staticcall_targets:
        p(f"\n── STATICCALL Targets {_SEP[22:]}")
        p(f"  Count: {len(staticcall_targets)}")
        all_safe = True
        for sc in staticcall_targets:
            if sc.target is not None:
                if sc.is_precompile:
                    gas_note = f", ~{sc.precompile_gas:,} gas base" if sc.precompile_gas else ""
                    p(f"    @ 0x{sc.offset:04X} → 0x{sc.target:02X} ({sc.precompile_name}{gas_note}) ✓")
                else:
                    p(f"    @ 0x{sc.offset:04X} → 0x{sc.target:040X} ✗ NOT a precompile")
                    all_safe = False
            else:
                p(f"    @ 0x{sc.offset:04X} → DYNAMIC (could not resolve statically) ⚠")
                all_safe = False
        if all_safe:
            p(f"  All targets are allowlisted precompiles ✓")
        else:
            p(f"  ⚠ Some targets could not be verified as precompiles")

    # ── Control Flow ──
    p(f"\n── Control Flow {_SEP[16:]}")
    p(f"  Basic blocks:     {len(cfg_blocks)}")
    edge_count = sum(len(b.successors) for b in cfg_blocks.values())
    p(f"  Edges:            {edge_count}")
    p(f"  Back edges:       {termination['loop_count']}"
      f" {'(no loops)' if not termination['has_loops'] else '⚠ LOOPS DETECTED'}")
    p(f"  Reachable:        {termination['reachable_blocks']} blocks")
    if termination["unreachable_blocks"] > 0:
        p(f"  Unreachable:      {termination['unreachable_blocks']} blocks")
    exits = termination["exit_points"]
    exit_str = ", ".join(f"{c}× {n}" for n, c in exits.items() if c > 0)
    p(f"  Exit points:      {sum(exits.values())} ({exit_str})")
    if termination["dynamic_jumps"]:
        p(f"  Dynamic jumps:    {len(termination['dynamic_jumps'])} ⚠")
        for off in termination["dynamic_jumps"]:
            p(f"    @ 0x{off:04X}")

    # ── Gas Estimation ──
    p(f"\n── Gas Estimation {_SEP[18:]}")

    if gas.get("exact"):
        p(f"  Min path cost:    {gas['min_path']:,} gas (static opcodes)")
        p(f"  Max path cost:    {gas['max_path']:,} gas (static opcodes)")
    else:
        p(f"  Max block sum:    {gas['max_path']:,} gas (upper bound, loops present)")
        p(f"  ⚠ {gas.get('reason', 'Exact estimation not possible')}")

    if gas.get("precompile_costs"):
        p(f"\n  Precompile costs (additive, not in path estimate):")
        for name, cost in gas["precompile_costs"]:
            p(f"    {name}: ~{cost:,} gas base")

    if gas.get("dynamic_sources"):
        p(f"\n  Dynamic gas sources: {', '.join(gas['dynamic_sources'])}")
        p(f"  (actual cost depends on runtime input sizes)")

    # ── Termination ──
    p(f"\n── Termination Analysis {_SEP[24:]}")
    if termination["provably_terminates"]:
        p(f"  Provably terminates:  YES ✓")
        p(f"  Reason:               No backward jumps, no dynamic jumps")
    elif termination["has_loops"]:
        p(f"  Provably terminates:  NO (loops detected)")
        p(f"  Loop back-edges:      {termination['loop_count']}")
        for src, dst in termination["back_edges"]:
            p(f"    0x{src:04X} → 0x{dst:04X}")
        p(f"  ⚠ Bounded only by gas provided at call time")
    else:
        p(f"  Provably terminates:  UNKNOWN")
        if termination["dynamic_jumps"]:
            p(f"  Reason:               {len(termination['dynamic_jumps'])} unresolved dynamic jump(s)")

    # ── Stack ──
    p(f"\n── Stack Analysis {_SEP[18:]}")
    p(f"  Max observed depth:  {stack['max_depth']}")
    if stack["underflows"]:
        p(f"  Stack underflows:    {len(stack['underflows'])} ⚠")
        for off, name, delta in stack["underflows"][:5]:
            p(f"    @ 0x{off:04X}: {name} (depth {delta})")
    else:
        p(f"  Stack underflows:    None ✓")
    p(f"  Stack overflow:      {'YES ⚠' if stack['overflow'] else 'No ✓'} ({stack['max_depth']} / 1024)")

    # ── Verdict ──
    p(f"\n{_DSEP}")

    issues: list[str] = []
    passes: list[str] = []

    if header.format == "spec" and header.valid:
        passes.append("Valid 8130 header")
    elif header.format == "legacy_v0":
        issues.append("Legacy header format (gas_limit removed from spec)")
    else:
        issues.append("No valid 8130 header")

    if not safety["forbidden"]:
        passes.append("No forbidden opcodes")
    else:
        n = len(set(i.opcode.name for i in safety["forbidden"]))
        issues.append(f"{n} forbidden opcode type(s) found")

    all_sc_safe = all(sc.is_precompile for sc in staticcall_targets)
    if not staticcall_targets:
        passes.append("No STATICCALL instructions (pure computation)")
    elif all_sc_safe:
        passes.append("All STATICCALL targets are allowlisted precompiles")
    else:
        issues.append("STATICCALL to non-precompile or unresolved target(s)")

    if termination["provably_terminates"]:
        passes.append("Provably terminates (no loops)")
    elif termination["has_loops"]:
        issues.append("Contains loops (no static termination proof)")
    else:
        issues.append("Termination not provable")

    if gas.get("exact") and gas["max_path"] > 0:
        passes.append(f"Static gas estimate: {gas['min_path']:,}–{gas['max_path']:,}")

    if not stack["underflows"] and not stack["overflow"]:
        passes.append("Stack discipline OK")

    if wrapper:
        issues.append("SandboxLib wrapper (STATICCALL proxy to external verifier)")

    if not issues:
        p("  VERDICT: ✅ SAFE")
    elif not safety["forbidden"] and all_sc_safe:
        p("  VERDICT: ⚠  CONDITIONALLY SAFE")
    else:
        p("  VERDICT: ✗  UNSAFE")

    p(_DSEP)
    for item in passes:
        p(f"  ✓ {item}")
    for item in issues:
        p(f"  ✗ {item}")
    p(_DSEP)
    p("")

    return "\n".join(lines)


def to_json(
    header: HeaderInfo,
    safety: dict,
    staticcall_targets: list[StaticCallTarget],
    cfg_blocks: dict[int, BasicBlock],
    termination: dict,
    gas: dict,
    stack: dict,
    wrapper: Optional[dict],
) -> dict:
    return {
        "header": {
            "valid": header.valid,
            "format": header.format,
            "version": header.version,
            "header_size": header.header_size,
            "bytecode_size": header.bytecode_size,
            "errors": header.errors,
        },
        "safety": {
            "safe": len(safety["forbidden"]) == 0,
            "forbidden_opcodes": [
                {"offset": i.offset, "name": i.opcode.name, "category": i.opcode.category}
                for i in safety["forbidden"]
            ],
            "instruction_count": safety["total_instructions"],
            "unique_opcodes": safety["unique_opcodes"],
            "opcode_counts": safety["opcode_counts"],
        },
        "staticcall_targets": [
            {
                "offset": sc.offset,
                "target": f"0x{sc.target:x}" if sc.target is not None else None,
                "is_precompile": sc.is_precompile,
                "precompile_name": sc.precompile_name,
                "precompile_gas": sc.precompile_gas,
            }
            for sc in staticcall_targets
        ],
        "control_flow": {
            "basic_blocks": len(cfg_blocks),
            "edges": sum(len(b.successors) for b in cfg_blocks.values()),
            "back_edges": termination["loop_count"],
            "has_loops": termination["has_loops"],
            "dynamic_jumps": termination["dynamic_jumps"],
            "reachable_blocks": termination["reachable_blocks"],
            "unreachable_blocks": termination["unreachable_blocks"],
            "exit_points": termination["exit_points"],
        },
        "gas": {
            "min_path": gas["min_path"],
            "max_path": gas["max_path"],
            "exact": gas.get("exact", False),
            "reason": gas.get("reason", ""),
            "dynamic_sources": gas.get("dynamic_sources", []),
            "precompile_costs": gas.get("precompile_costs", []),
        },
        "termination": {
            "provably_terminates": termination["provably_terminates"],
            "has_loops": termination["has_loops"],
            "loop_count": termination["loop_count"],
            "back_edges": [
                {"from": f"0x{s:04x}", "to": f"0x{d:04x}"}
                for s, d in termination["back_edges"]
            ],
        },
        "stack": {
            "max_depth": stack["max_depth"],
            "underflow_count": len(stack["underflows"]),
            "overflow": stack["overflow"],
        },
        "wrapper": wrapper,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Main Analysis Pipeline
# ═══════════════════════════════════════════════════════════════════════════════


def analyze(bytecode: bytes, show_disasm: bool = False, output_json: bool = False) -> str | dict:
    """Run all analysis passes on the given bytecode."""
    header = parse_header(bytecode)

    # Disassemble full bytecode and the code portion (after header)
    all_instructions = disassemble(bytecode)
    code_start = header.header_size if header.format != "none" else 0
    code_instructions = disassemble(bytecode, start=code_start)

    # Detect wrapper
    wrapper = detect_wrapper(bytecode, header)

    # Safety (on code portion only, skip header metadata)
    safety = analyze_safety(code_instructions)

    # CFG (code portion)
    cfg_blocks = build_cfg(code_instructions)
    entry = code_start

    # Termination
    termination = analyze_termination(cfg_blocks, entry)

    # STATICCALL targets
    sc_targets = analyze_staticcall_targets(code_instructions, cfg_blocks)

    # Gas estimation
    gas = estimate_gas(cfg_blocks, entry, termination, sc_targets)

    # Stack
    stack = analyze_stack(cfg_blocks, entry, termination)

    if output_json:
        return to_json(header, safety, sc_targets, cfg_blocks, termination, gas, stack, wrapper)

    return format_report(
        bytecode, header, safety, sc_targets, cfg_blocks,
        termination, gas, stack, wrapper, show_disasm,
        code_instructions, all_instructions,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════


def load_bytecode(args: argparse.Namespace) -> bytes:
    """Load bytecode from the specified source."""
    if args.hex:
        raw = args.hex.strip()
        if raw.startswith("0x") or raw.startswith("0X"):
            raw = raw[2:]
        return bytes.fromhex(raw)

    if args.file:
        text = Path(args.file).read_text().strip()
        if text.startswith("0x") or text.startswith("0X"):
            text = text[2:]
        return bytes.fromhex(text)

    if args.artifact:
        artifact = json.loads(Path(args.artifact).read_text())
        # Foundry artifact format
        bc = artifact.get("deployedBytecode", {}).get("object", "")
        if not bc:
            bc = artifact.get("bytecode", {}).get("object", "")
        if not bc:
            print("Error: could not find bytecode in artifact", file=sys.stderr)
            sys.exit(1)
        if bc.startswith("0x"):
            bc = bc[2:]
        return bytes.fromhex(bc)

    print("Error: specify --hex, --file, or --artifact", file=sys.stderr)
    sys.exit(1)


def _run_batch(
    artifact_dir: str,
    output_dir: str,
    disasm: bool = False,
    name_filter: str = "",
) -> None:
    """Run analysis on all Foundry artifacts in a directory tree."""
    import fnmatch

    artifact_path = Path(artifact_dir)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    artifacts = sorted(artifact_path.rglob("*.json"))
    artifacts = [
        a for a in artifacts
        if not a.name.startswith(".")
        and "build-info" not in str(a)
        and ".dbg." not in a.name
    ]

    if name_filter:
        artifacts = [a for a in artifacts if fnmatch.fnmatch(a.stem, name_filter)]

    summary: list[dict] = []

    for art_file in artifacts:
        try:
            data = json.loads(art_file.read_text())
            bc_hex = data.get("deployedBytecode", {}).get("object", "")
            if not bc_hex or bc_hex == "0x":
                continue
            if bc_hex.startswith("0x"):
                bc_hex = bc_hex[2:]
            bytecode = bytes.fromhex(bc_hex)
            if len(bytecode) == 0:
                continue
        except Exception:
            continue

        name = art_file.stem
        rel = art_file.relative_to(artifact_path)
        print(f"  Analyzing {rel} ({len(bytecode)} bytes)...")

        text_report = analyze(bytecode, show_disasm=disasm, output_json=False)
        json_report = analyze(bytecode, show_disasm=False, output_json=True)
        json_report["_meta"] = {
            "artifact": str(rel),
            "contract": name,
            "bytecode_size": len(bytecode),
        }

        # Write individual reports
        (out_path / f"{name}.txt").write_text(text_report)
        (out_path / f"{name}.json").write_text(json.dumps(json_report, indent=2))

        # Extract verdict for summary
        safe = (
            json_report["safety"]["safe"]
            and all(t["is_precompile"] for t in json_report["staticcall_targets"])
        )
        summary.append({
            "contract": name,
            "bytecode_size": len(bytecode),
            "header": json_report["header"]["format"],
            "header_valid": json_report["header"]["valid"],
            "forbidden_opcodes": len(json_report["safety"]["forbidden_opcodes"]),
            "staticcalls": len(json_report["staticcall_targets"]),
            "staticcall_targets_safe": all(
                t["is_precompile"] for t in json_report["staticcall_targets"]
            ),
            "has_loops": json_report["termination"]["has_loops"],
            "provably_terminates": json_report["termination"]["provably_terminates"],
            "max_gas_path": json_report["gas"]["max_path"],
            "sandbox_safe": safe and json_report["header"]["valid"],
        })

    # Write summary
    summary_path = out_path / "SUMMARY.json"
    summary_path.write_text(json.dumps(summary, indent=2))

    # Print summary table
    print(f"\n{'═' * 92}")
    print(f"  {'Contract':<25s} {'Size':>6s}  {'Header':<8s} {'Forbidden':>9s} {'Loops':>6s} {'Terminates':>10s} {'Safe':>6s}")
    print(f"{'─' * 92}")
    for row in summary:
        term = "YES" if row["provably_terminates"] else "NO"
        safe_str = "✅" if row["sandbox_safe"] else "✗"
        loops = "yes ⚠" if row["has_loops"] else "no"
        print(
            f"  {row['contract']:<25s} {row['bytecode_size']:>5d}B  {row['header']:<8s}"
            f" {row['forbidden_opcodes']:>9d}  {loops:>6s} {term:>10s} {safe_str:>6s}"
        )
    print(f"{'═' * 92}")
    print(f"\n  Reports written to {out_path}/")
    print(f"  Summary: {summary_path}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="EIP-8130 Sandbox Verifier Bytecode Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python analyze.py --hex 600956813000640005b363d3d37...
  python analyze.py --file verifier.hex --disasm
  python analyze.py --artifact out/BLSVerifier.sol/BLSVerifier.json
  python analyze.py --hex ... --json
  python analyze.py --batch out/ -o reports/
""",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--hex", help="Raw bytecode as hex string (with or without 0x prefix)")
    group.add_argument("--file", help="Path to file containing hex bytecode")
    group.add_argument("--artifact", help="Path to Foundry JSON artifact")
    group.add_argument("--batch", metavar="DIR", help="Analyze all Foundry artifacts in DIR")
    parser.add_argument("--filter", default="", help="Glob filter for --batch (e.g. '*Verifier')")
    parser.add_argument("--disasm", action="store_true", help="Include full disassembly")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of text")
    parser.add_argument("-o", "--output", help="Write output to file (or directory for --batch)")

    args = parser.parse_args()

    if args.batch:
        out_dir = args.output or "reports"
        filt = getattr(args, "filter", "")
        print(f"\n  Batch analyzing artifacts in {args.batch}{'  (filter: ' + filt + ')' if filt else ''}...\n")
        _run_batch(args.batch, out_dir, disasm=args.disasm, name_filter=filt)
        return

    try:
        bytecode = load_bytecode(args)
    except Exception as e:
        print(f"Error loading bytecode: {e}", file=sys.stderr)
        sys.exit(1)

    if len(bytecode) == 0:
        print("Error: empty bytecode", file=sys.stderr)
        sys.exit(1)

    result = analyze(bytecode, show_disasm=args.disasm, output_json=args.json)

    output = json.dumps(result, indent=2) if args.json else result

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output)
        print(f"Report written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
