#!/usr/bin/env python3
"""Generate a deterministic VM-like Unidbg text trace for benchmarks/tests.

The output is synthetic. It is deliberately not committed as a large fixture.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def instruction(template: str, addr: int, disasm: str, values: str = "") -> str:
    suffix = f" {values}" if values else ""
    return (
        f"[00:00:00 001][synthetic.so 0x{addr - 0x40000000:x}] [00000000] "
        f"0x{addr:x}: \"{disasm}\"{suffix}\n"
    )


def build_block() -> list[str]:
    return [
        instruction("", 0x40100000, "mov x8, #0", "=> x8=0x0"),
        instruction("", 0x40100004, "add x8, x8, #1", "x8=0x0 => x8=0x1"),
        instruction("", 0x40100008, "eor x10, x10, x8", "x10=0x1 x8=0x1 => x10=0x0"),
        instruction("", 0x4010000C, "add x9, x9, #4", "x9=0x2000 => x9=0x2004"),
        instruction("", 0x40100010, "br x9", "x9=0x2004"),
        instruction("", 0x40102000, "add x10, x10, x11", "x10=0x0 x11=0x2 => x10=0x2"),
        instruction(
            "",
            0x40102004,
            "str x10, [x12]",
            "; mem[WRITE] abs=0x1000 x10=0x2 x12=0x1000 => x10=0x2",
        ),
        instruction("", 0x40102008, "sub x9, x9, #4", "x9=0x2004 => x9=0x2000"),
        instruction("", 0x4010200C, "br x9", "x9=0x2000"),
        instruction("", 0x40102010, "eor x10, x10, x13", "x10=0x2 x13=0x1 => x10=0x3"),
        instruction("", 0x40102014, "mul x14, x10, x15", "x10=0x3 x15=0x7 => x14=0x15"),
        instruction("", 0x40102018, "sub x9, x9, #4", "x9=0x2000 => x9=0x1ffc"),
        instruction("", 0x4010201C, "br x9", "x9=0x1ffc"),
        instruction("", 0x40101FFC, "cmp x9, #0x1000", "x9=0x1ffc"),
        instruction("", 0x4010201C, "b.ne 0x40100000", "x9=0x1ffc"),
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--lines", required=True, type=int)
    args = parser.parse_args()
    if args.lines <= 0:
        raise SystemExit("--lines must be positive")

    block = build_block()
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n")
        written = 0
        while written < args.lines:
            take = min(len(block), args.lines - written)
            handle.writelines(block[:take])
            written += take


if __name__ == "__main__":
    main()
