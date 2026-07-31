#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
MAX_FILE_LINES = 250
MAX_MAIN_LINES = 40
BANNED_GOD_FILES = {
    "src/application/service.rs",
    "src/infrastructure/postgres.rs",
    "src/transport/grpc.rs",
}
LAYER_RULES = {
    "domain": (
        "sqlx",
        "tonic",
        "axum",
        "platform_proto",
        "crate::application",
        "crate::infrastructure",
        "crate::transport",
    ),
    "application": (
        "sqlx",
        "tonic",
        "axum",
        "platform_proto",
        "crate::infrastructure",
        "crate::transport",
    ),
    "infrastructure": ("crate::transport",),
    "transport": ("sqlx",),
}
FN_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)")


def function_end(lines: list[str], start: int) -> int | None:
    depth = 0
    opened = False
    for index in range(start, len(lines)):
        line = strip_strings_and_comments(lines[index])
        opens = line.count("{")
        closes = line.count("}")
        if opens:
            opened = True
        depth += opens - closes
        if opened and depth <= 0:
            return index
    return None


def strip_strings_and_comments(line: str) -> str:
    line = line.split("//", 1)[0]
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', line)


def check_file(path: Path) -> list[str]:
    relative = path.relative_to(ROOT).as_posix()
    lines = path.read_text().splitlines()
    errors: list[str] = []
    if len(lines) > MAX_FILE_LINES:
        errors.append(f"{relative}: {len(lines)} lines exceeds {MAX_FILE_LINES}")
    if relative == "src/main.rs" and len(lines) > MAX_MAIN_LINES:
        errors.append(f"{relative}: {len(lines)} lines exceeds main limit {MAX_MAIN_LINES}")
    if relative in BANNED_GOD_FILES:
        errors.append(f"{relative}: banned god-file name")

    parts = relative.split("/")
    layer = parts[1] if len(parts) > 2 and parts[0] == "src" else None
    if layer in LAYER_RULES:
        content = "\n".join(lines)
        for forbidden in LAYER_RULES[layer]:
            if forbidden in content:
                errors.append(f"{relative}: layer '{layer}' must not reference '{forbidden}'")

    return errors


def main() -> int:
    errors: list[str] = []
    for path in sorted(SRC.rglob("*.rs")):
        errors.extend(check_file(path))
    if errors:
        print("architecture check failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("architecture check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
