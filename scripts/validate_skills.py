#!/usr/bin/env python3
"""Validate Hermes skill files in this repository without external dependencies."""
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
MAX_DESCRIPTION = 1024
MAX_CONTENT = 100_000
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    if not text.startswith("---\n"):
        raise ValueError("frontmatter must start at byte 0 with ---")
    end = text.find("\n---\n", 4)
    if end == -1:
        raise ValueError("frontmatter closing --- not found")
    raw = text[4:end]
    body = text[end + len("\n---\n"):]
    data: dict[str, str] = {}
    for line in raw.splitlines():
        if not line.strip() or line.startswith(" "):
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            data[key.strip()] = value.strip().strip('"')
    return data, body


def validate(path: Path) -> list[str]:
    errors: list[str] = []
    text = path.read_text()
    if len(text) > MAX_CONTENT:
        errors.append(f"{path}: file exceeds {MAX_CONTENT} chars")
    try:
        fm, body = parse_frontmatter(text)
    except Exception as exc:
        return [f"{path}: {exc}"]
    name = fm.get("name", "")
    desc = fm.get("description", "")
    if not name:
        errors.append(f"{path}: missing name")
    elif not NAME_RE.match(name):
        errors.append(f"{path}: invalid name {name!r}")
    if not desc:
        errors.append(f"{path}: missing description")
    elif len(desc) > MAX_DESCRIPTION:
        errors.append(f"{path}: description exceeds {MAX_DESCRIPTION} chars")
    if not body.strip():
        errors.append(f"{path}: body is empty")
    for rel in re.findall(r"(?:references|templates|scripts|assets)/[-A-Za-z0-9_./]+", text):
        rel = rel.rstrip('`.,)')
        candidate = path.parent / rel
        if not candidate.exists():
            errors.append(f"{path}: linked file missing: {rel}")
    return errors


def main() -> int:
    skills = sorted(ROOT.glob("*/SKILL.md"))
    if not skills:
        print("no SKILL.md files found", file=sys.stderr)
        return 1
    errors: list[str] = []
    for skill in skills:
        errors.extend(validate(skill))
    if errors:
        print("Skill validation failed:", file=sys.stderr)
        for err in errors:
            print(f"- {err}", file=sys.stderr)
        return 1
    print(f"Validated {len(skills)} skill(s):")
    for skill in skills:
        print(f"- {skill.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
