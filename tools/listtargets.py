#!/usr/bin/env python3
"""List fuzz targets registered in driver.cpp."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Sequence

RUN_FUNCTION_RE = re.compile(r"\bvoid\s+Driver::Run\s*\(")
TARGET_RE = re.compile(
    r"""
    \b(?:if|else\s+if)
    \s*\(\s*
    target
    \s*==\s*
    "([^"\\]*(?:\\.[^"\\]*)*)"
    \s*\)
    """,
    re.VERBOSE,
)


def strip_cpp_comments(source: str) -> str:
    """Remove C++ line and block comments while preserving string literals."""
    output: list[str] = []
    i = 0
    state: str | None = None

    while i < len(source):
        char = source[i]
        next_char = source[i + 1] if i + 1 < len(source) else ""

        if state is None:
            if char in {'"', "'"}:
                state = char
                output.append(char)
                i += 1
            elif char == "/" and next_char == "/":
                i += 2
                while i < len(source) and source[i] != "\n":
                    i += 1
                if i < len(source):
                    output.append("\n")
                    i += 1
            elif char == "/" and next_char == "*":
                i += 2
                while i + 1 < len(source) and not (
                    source[i] == "*" and source[i + 1] == "/"
                ):
                    if source[i] == "\n":
                        output.append("\n")
                    i += 1
                i += 2 if i + 1 < len(source) else 0
            else:
                output.append(char)
                i += 1
        else:
            output.append(char)
            if char == "\\" and i + 1 < len(source):
                output.append(source[i + 1])
                i += 2
            elif char == state:
                state = None
                i += 1
            else:
                i += 1

    return "".join(output)


def find_repo_root() -> Path:
    """Find the repository root by walking up from this script."""
    current = Path(__file__).resolve().parent
    while current != current.parent:
        if (current / "driver.cpp").is_file():
            return current
        current = current.parent
    raise ValueError("could not locate repository root containing driver.cpp")


def find_matching_brace(source: str, open_brace: int) -> int:
    """Return the offset of the closing brace matching open_brace."""
    depth = 0
    state: str | None = None
    i = open_brace

    while i < len(source):
        char = source[i]

        if state is None:
            if char in {'"', "'"}:
                state = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return i
            i += 1
        else:
            if char == "\\" and i + 1 < len(source):
                i += 2
            elif char == state:
                state = None
                i += 1
            else:
                i += 1

    raise ValueError("could not find the end of Driver::Run()")


def extract_run_body(source: str) -> str:
    """Extract the Driver::Run() function body from driver.cpp contents."""
    match = RUN_FUNCTION_RE.search(source)
    if match is None:
        raise ValueError("could not find Driver::Run()")

    open_brace = source.find("{", match.end())
    if open_brace == -1:
        raise ValueError("could not find the start of Driver::Run()")

    close_brace = find_matching_brace(source, open_brace)
    return source[open_brace + 1 : close_brace]


def extract_targets(driver_path: Path) -> list[str]:
    """Extract fuzz target names from the Driver::Run() dispatch block."""
    source = driver_path.read_text(encoding="utf-8")
    uncommented_source = strip_cpp_comments(source)
    run_body = extract_run_body(uncommented_source)
    targets = [match.group(1) for match in TARGET_RE.finditer(run_body)]

    if not targets:
        raise ValueError(f"no targets found in {driver_path}")

    duplicates = sorted({target for target in targets if targets.count(target) > 1})
    if duplicates:
        raise ValueError(f"duplicate targets found: {', '.join(duplicates)}")

    return targets


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="List fuzz target names from driver.cpp's Driver::Run()."
    )
    parser.add_argument(
        "--format",
        choices=("json",),
        default="json",
        help="Output format. Currently only json is supported.",
    )
    parser.add_argument(
        "--driver",
        type=Path,
        default=None,
        help="Path to driver.cpp. Defaults to the repository driver.cpp.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    driver_path = (
        args.driver if args.driver is not None else find_repo_root() / "driver.cpp"
    )

    try:
        targets = extract_targets(driver_path)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(targets, indent=2))
        return 0

    print(f"Error: unsupported format: {args.format}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
