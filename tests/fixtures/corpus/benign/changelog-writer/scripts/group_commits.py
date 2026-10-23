#!/usr/bin/env python3
"""Group commits into changelog sections. Pure function over stdin, no I/O beyond stdout."""

from __future__ import annotations

import re
import sys

PREFIXES = {"feat": "Added", "fix": "Fixed", "perf": "Changed", "refactor": "Changed", "docs": "Changed"}


def group(lines: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in lines:
        m = re.match(r"^[0-9a-f]+\s+(\w+)(\(.+\))?!?:\s*(.+)$", line.strip())
        if not m:
            continue
        section = PREFIXES.get(m.group(1), "Changed")
        out.setdefault(section, []).append(m.group(3))
    return out


if __name__ == "__main__":
    for section, items in group(sys.stdin.readlines()).items():
        print(f"### {section}")
        for item in items:
            print(f"- {item}")
