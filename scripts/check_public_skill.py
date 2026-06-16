#!/usr/bin/env python3
"""Public-safety gate for the rust-security-auditor skill.

Verifies the published skill is free of private/personal assumptions and keeps
the expected public structure. Complements scripts/validate_skills.py (which
checks generic frontmatter/size/links for every skill).

Checks:
- SKILL.md frontmatter parses as YAML; name == rust-security-auditor.
- description <= 1024 chars; SKILL.md <= 100000 chars.
- every referenced references/*.md and templates/*.md exists.
- no broken local markdown links.
- no private terms (bare names, and PostgreSQL 18 / UUIDv8 used as MANDATORY policy;
  bare UUIDv8 as an example is allowed).
- required public sections exist.

Usage:  python3 scripts/check_public_skill.py
"""
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL_DIR = os.path.join(ROOT, "rust-security-auditor")
SKILL = os.path.join(SKILL_DIR, "SKILL.md")
EXPECTED_NAME = "rust-security-auditor"
MAX_DESC = 1024
MAX_CHARS = 100_000

# Bare private terms: must never appear anywhere in the skill (case-insensitive).
PRIVATE_BARE = [
    r"\bgelo\b",
    r"\bskaliza\b",
    r"\bmonetics\b",
    r"\bjo[ãa]o\b",
    r"\bc3b\b",
    r"opus 4\.8",
    r"gpt 5\.5",
    r"hard user invariants?",
    r"\bthis user\b",            # covers "this user", "this user's", "for this user"
    r"\bpostgresql 18\b",        # public skill must not pin PG 18 as policy
]

# Mandatory-policy phrasings for UUIDv8 (bare "UUIDv8" as an example IS allowed).
# Negative lookbehind avoids matching "do not require UUIDv8" / "unless ... UUIDv8".
UUIDV8_MANDATORY = [
    r"expect uuidv8",
    r"uuidv8 everywhere",
    r"uuidv8 only",
    r"uuidv8 invariant",
    r"uuidv8 (is|are) (not )?(a )?(preference|expected|mandatory|policy default|invariant)",
    r"(?<!not )(?<!don't )mandatory uuidv8",
    r"postgresql 18 and uuidv8",
]

REQUIRED_SECTIONS = [
    "Surface-Triggered Modules",
    "Required External Coverage Pass",
    "Coverage Matrix",
    "Project-Specific Policy Discovery",
    "Business Logic Abuse Review",
    "Fuzz, Miri, and Sanitizer Gate",
    "MCP",
    "RAG",
    "SLSA",
]

results = []  # (ok, label, detail)


def check(ok, label, detail=""):
    results.append((bool(ok), label, detail))


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def parse_frontmatter(text):
    if not text.startswith("---\n"):
        return None, "frontmatter must start at byte 0 with ---"
    end = text.find("\n---\n", 4)
    if end == -1:
        return None, "frontmatter closing --- not found"
    raw = text[4:end]
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(raw)
        if not isinstance(data, dict):
            return None, "frontmatter is not a YAML mapping"
        return {k: v for k, v in data.items()}, None
    except ImportError:
        data, key = {}, None
        for line in raw.splitlines():
            if not line.strip() or line.startswith((" ", "\t")):
                continue
            if ":" in line:
                key, val = line.split(":", 1)
                data[key.strip()] = val.strip().strip('"')
        return data, None
    except Exception as exc:  # pragma: no cover
        return None, "YAML parse error: %s" % exc


skill_text = read(SKILL)
fm, fm_err = parse_frontmatter(skill_text)
check(fm is not None, "SKILL.md frontmatter parses as YAML", fm_err or "")
name = str((fm or {}).get("name", ""))
desc = str((fm or {}).get("description", ""))
check(name == EXPECTED_NAME, "name == %s" % EXPECTED_NAME, "name=%r" % name)
check(0 < len(desc) <= MAX_DESC, "description length 1..%d" % MAX_DESC, "len=%d" % len(desc))
check(len(skill_text) <= MAX_CHARS, "SKILL.md chars <= %d" % MAX_CHARS, "chars=%d" % len(skill_text))

# referenced references/templates files exist
mentioned = sorted(set(re.findall(r"(?:references|templates)/[A-Za-z0-9._-]+\.md", skill_text)))
missing = [r for r in mentioned if not os.path.isfile(os.path.join(SKILL_DIR, r))]
check(not missing, "referenced references/templates exist", "missing: %s" % missing if missing else "%d ok" % len(mentioned))

# all skill markdown files (for term + link scanning)
md_files = [SKILL] + sorted(glob.glob(os.path.join(SKILL_DIR, "references", "*.md"))) \
                   + sorted(glob.glob(os.path.join(SKILL_DIR, "templates", "*.md")))

# broken local markdown links
broken = []
link_re = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
for f in md_files:
    base = os.path.dirname(f)
    for target in link_re.findall(read(f)):
        t = target.strip()
        if t.startswith(("http://", "https://", "#", "mailto:", "tel:")):
            continue
        t = t.split("#", 1)[0].split("?", 1)[0]
        if t and not os.path.isfile(os.path.join(base, t)):
            broken.append("%s -> %s" % (os.path.relpath(f, ROOT), target))
check(not broken, "no broken local markdown links", "broken: %s" % broken if broken else "checked %d files" % len(md_files))

# private-term scan across the whole skill dir
bare_hits, mand_hits = [], []
for f in md_files:
    low = read(f).lower()
    rel = os.path.relpath(f, ROOT)
    for pat in PRIVATE_BARE:
        if re.search(pat, low):
            bare_hits.append("%s ~ /%s/" % (rel, pat))
    for pat in UUIDV8_MANDATORY:
        if re.search(pat, low):
            mand_hits.append("%s ~ /%s/" % (rel, pat))
check(not bare_hits, "no bare private terms (incl. mandatory PostgreSQL 18)", "hits: %s" % bare_hits if bare_hits else "clean")
check(not mand_hits, "no mandatory-UUIDv8 phrasing (example usage allowed)", "hits: %s" % mand_hits if mand_hits else "clean")

# required public sections
for s in REQUIRED_SECTIONS:
    check(s in skill_text, "SKILL.md contains %r" % s)

passed = sum(1 for ok, _, _ in results if ok)
failed = [r for r in results if not r[0]]
print("rust-security-auditor public-safety check")
print("=" * 60)
for ok, label, detail in results:
    print("[%s] %s%s" % ("PASS" if ok else "FAIL", label, "  (%s)" % detail if detail else ""))
print("=" * 60)
print("%d passed, %d failed, %d total" % (passed, len(failed), len(results)))
sys.exit(1 if failed else 0)
