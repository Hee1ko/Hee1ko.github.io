#!/usr/bin/env python3
"""Confidentiality gate for the public hwk-site repo.

This repo is public. The machine it is authored on also holds an Amazon-internal
tool, real customer case data, and a private career-prep repo. A single careless
`git add .` would publish named enterprise customers and internal system names
under a real name, permanently and indexed. This script is the mechanical stop.

Blocking findings exit non-zero. Warnings are reported but do not block, because
a gate that cries wolf gets disabled, and then it protects nothing.

Usage:
    scrub.py                  # staged content (pre-commit hook)
    scrub.py --all            # every tracked file (CI)
    scrub.py --history        # every blob in every commit (pre-push)
    scrub.py --paths a.html   # specific files
    scrub.py --stdin          # text on stdin (for rendered-DOM checks)
    scrub.py --self-test      # verify the gate catches planted violations

Suppress a false positive with `scrum-ok`-style pragma on the same line:
    scrub-ok: <reason>
An empty reason is not accepted. Every suppression is counted in the summary so
they stay visible instead of silently accumulating.

Design notes worth keeping in mind if you edit this:

* In --staged mode content is read from the git INDEX, not the working tree.
  Reading the worktree lets "fix it locally, commit the staged bad version"
  walk straight through the gate. That is a real and easy bypass.
* PDFs are extracted with pdftotext. PDF text is Flate-compressed, so a plain
  grep sees nothing -- the highest-risk artifact would otherwise be invisible.
* Matched text is NOT echoed for confidential-name hits. Terminal scrollback
  ends up in screen shares and shell history.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import unicodedata
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HASH_FILE = REPO / "tools" / "banned-hashes.txt"

# Plaintext term list, deliberately OUTSIDE this public repo. A file listing our
# customers' names would defeat the entire point of the gate.
LOCAL_TERMS = Path.home() / ".config" / "hwk-site" / "banned-terms.txt"

BLOCK, WARN = "BLOCK", "WARN"

# Public Amazon/AWS hosts. Linking real AWS documentation is normal and must not
# trip the internal-hostname rule.
PUBLIC_HOSTS = {
    "aws.amazon.com", "docs.aws.amazon.com", "console.aws.amazon.com",
    "signin.aws.amazon.com", "repost.aws", "amazon.com", "www.amazon.com",
    "amazon.jobs", "www.amazon.jobs", "aboutamazon.com", "www.aboutamazon.com",
    "press.aboutamazon.com", "sustainability.aboutamazon.com",
}

# Account IDs that are documentation placeholders, not real accounts.
DUMMY_ACCOUNTS = {"111122223333", "123456789012", "000000000000", "012345678901"}

# Data artifacts that must never be committed. casework-rag's index/ and
# catalog.md live one directory away from a repo root and hold live case text.
DENY_SUFFIXES = {
    ".db", ".sqlite", ".sqlite3", ".jsonl", ".npy", ".npz", ".csv", ".tsv",
    ".env", ".pem", ".key", ".p12", ".keychain", ".pkl", ".parquet",
}
DENY_NAMES = {"catalog.md", ".env", "credentials", "config.json"}

# Binary formats the text scanner cannot read. PDFs are handled separately.
SKIP_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".svgz",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".zip", ".gz", ".mp4", ".webm",
}

# Files the gate must not police, or it flags its own rule definitions.
SELF_EXEMPT = {
    "tools/scrub.py", "tools/make-hashes.py", "tools/banned-hashes.txt",
    "tools/README.md",
}

# --------------------------------------------------------------------------
# Regex rules. All safe to publish -- they describe shapes, not secrets.
# (category, severity, pattern, explanation)
# --------------------------------------------------------------------------
RULES: list[tuple[str, str, re.Pattern[str], str]] = [
    # --- credentials ---
    ("credential", BLOCK, re.compile(r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
     "AWS access key ID"),
    ("credential", BLOCK, re.compile(r"aws_secret_access_key|aws_session_token", re.I),
     "AWS secret material"),
    ("credential", BLOCK, re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key block"),
    ("credential", BLOCK, re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}"), "Slack token"),
    ("credential", BLOCK, re.compile(r"\bgh[pousr]_[0-9A-Za-z]{20,}"), "GitHub token"),
    ("credential", BLOCK, re.compile(r"\bsk-(?:ant-)?[0-9A-Za-z_-]{20,}"), "LLM provider API key"),
    # --- identifiers ---
    ("case-id", BLOCK, re.compile(r"(?<!\d)\d{17}(?!\d)"), "17-digit support case ID"),
    ("arn", BLOCK, re.compile(r"arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:\d{12}:"),
     "ARN containing a real account ID"),
    # --- internal infrastructure ---
    ("internal-host", BLOCK,
     re.compile(r"\b[A-Za-z0-9][A-Za-z0-9.-]*\.(?:amazon\.(?:com|dev)|a2z\.com|aws\.dev)\b"),
     "Amazon-internal hostname"),
    ("internal-host", BLOCK, re.compile(r"\bcorp\.amazon\.com\b"), "Amazon corp hostname"),
    ("internal-host", BLOCK, re.compile(r"\bquip-amazon\.com\b"), "internal Quip"),
    ("internal-git", BLOCK,
     re.compile(r"(?:git@ssh\.|ssh://|https://)[A-Za-z0-9.-]*(?:gitlab\.aws\.dev|code\.amazon)"),
     "internal git remote"),
    # --- internal system names. Case-sensitive whole words: these are proper
    #     nouns, and lowercase spellings are usually ordinary English. ---
    ("internal-system", BLOCK,
     re.compile(r"\b(?:Dante|Isengard|Midway|mwinit|Harbinger|Heimdall|Baywatch|Tumbler"
                r"|Skyhook|JESOps|phonetool|Kumo|Bindle|Peculiar|Elmo|Magma"
                r"|CloudAuth|Kingpin|Weblab|CRUX|Quip)\b"),
     "Amazon-internal system name"),
    ("internal-system", BLOCK, re.compile(r"\bK2\b"), "Amazon-internal system name"),
    ("internal-system", BLOCK, re.compile(r"\bSIM\b(?! card)|\bSIM-T\b"),
     "Amazon-internal ticketing"),
    ("internal-system", BLOCK,
     re.compile(r"brazil[- ](?:build|workspace|recursive|path)", re.I),
     "Amazon-internal build system"),
    ("internal-system", BLOCK,
     re.compile(r"\bada credentials\b|\bkiro-cli\b|\bcommand-center\b|\bisengard\b", re.I),
     "Amazon-internal tooling"),
    # --- personal contact detail we deliberately keep off a scraped page ---
    ("personal", BLOCK,
     re.compile(r"(?:\+?61[\s.-]?4|\b04)\d{2}[\s.-]?\d{3}[\s.-]?\d{3}\b"),
     "Australian mobile number"),
    # --- font licensing. Roobert PRO is commercial and unlicensed here. ---
    ("font-license", BLOCK, re.compile(r"Roobert", re.I), "unlicensed commercial font"),
    # --- internal performance data. Not confidential, but not externally
    #     verifiable either, and it reads as unearned in public. ---
    ("internal-jargon", WARN,
     re.compile(r"(?:assessment|score[ds]?|mark)\D{0,24}\b9\d\s?%", re.I),
     "internal assessment score"),
    ("internal-jargon", WARN,
     re.compile(r"\bSVO profile\b|\bBigData profile\b|\bML/AI TFC\b|\bTechnical Field Community\b"
                r"|\bL200 Agentic AI Ambassador\b|\bGenAI Foundations Ambassador\b"
                r"|\bProject Tensei\b|\bTop performer in cohort\b", re.I),
     "internal terminology or an unverifiable internal claim"),
]

SUPPRESS = re.compile(r"scrub-ok:\s*(\S.*)")


# --------------------------------------------------------------------------
# Term lists
# --------------------------------------------------------------------------
def load_hashed_terms() -> tuple[str, set[str], int]:
    if not HASH_FILE.exists():
        return "", set(), 0
    salt, hashes, max_n = "", set(), 1
    for raw in HASH_FILE.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            if line.startswith("# salt:"):
                salt = line.split(":", 1)[1].strip()
            elif line.startswith("# max-ngram:"):
                max_n = int(line.split(":", 1)[1].strip())
            continue
        hashes.add(line)
    return salt, hashes, max_n


def load_local_terms() -> list[str]:
    if not LOCAL_TERMS.exists():
        return []
    return [ln.strip() for ln in LOCAL_TERMS.read_text().splitlines()
            if ln.strip() and not ln.strip().startswith("#")]


def normalize(text: str) -> list[str]:
    text = unicodedata.normalize("NFKC", text)
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).split()


def digest(salt: str, phrase: str) -> str:
    return hashlib.sha256((salt + "\x1f" + phrase).encode()).hexdigest()[:32]


def hashed_hits(line: str, salt: str, hashes: set[str], max_n: int) -> list[str]:
    """Find banned literal terms by hashing every short n-gram on the line.

    The n-gram step is why "State Street" is caught as a phrase, and why the
    same term is caught after HTML tags are stripped out of the text.
    """
    if not hashes:
        return []
    tokens = normalize(line)
    found = []
    for n in range(1, max_n + 1):
        for i in range(len(tokens) - n + 1):
            phrase = " ".join(tokens[i:i + n])
            if digest(salt, phrase) in hashes:
                found.append(phrase)
    return found


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------
class Finding:
    # Categories whose matched text must never be printed.
    QUIET = {"confidential-name", "credential", "personal"}

    def __init__(self, path, lineno, category, severity, why, excerpt, match=""):
        self.path, self.lineno = path, lineno
        self.category, self.severity = category, severity
        self.why, self.excerpt, self.match = why, excerpt, match

    def render(self) -> str:
        if self.category in self.QUIET:
            detail = f"{self.why} <redacted, {len(self.match)} chars>" if self.match else self.why
            body = "        > <line withheld to keep it out of terminal history>"
        else:
            detail = self.why
            body = f"        > {self.excerpt}"
        return f"{self.severity:5} {self.path}:{self.lineno}  [{self.category}] {detail}\n{body}"


def scan_text(path, text, salt, hashes, max_n, local_terms) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    suppressed = 0
    local_res = [(t, re.compile(r"\b" + re.escape(t) + r"\b", re.I)) for t in local_terms]

    for lineno, line in enumerate(text.splitlines(), 1):
        if SUPPRESS.search(line):
            suppressed += 1
            continue
        excerpt = line.strip()[:120]

        for category, severity, pattern, why in RULES:
            m = pattern.search(line)
            if not m:
                continue
            hit = m.group(0)
            if category == "internal-host" and hit.lower().lstrip(".") in PUBLIC_HOSTS:
                continue
            shown = why if category in Finding.QUIET else f"{why}: {hit}"
            findings.append(Finding(path, lineno, category, severity, shown, excerpt, hit))

        # 12-digit account IDs, documentation placeholders allowed.
        for m in re.finditer(r"(?<![\d.])\d{12}(?![\d.])", line):
            if m.group(0) not in DUMMY_ACCOUNTS:
                findings.append(Finding(path, lineno, "account-id", BLOCK,
                                        f"12-digit AWS account ID: {m.group(0)}", excerpt))
                break

        hit_name = False
        for term, pattern in local_res:
            m = pattern.search(line)
            if m:
                findings.append(Finding(path, lineno, "confidential-name", BLOCK,
                                        "banned term from the private list", excerpt, m.group(0)))
                hit_name = True
                break
        if not hit_name and not local_res:  # hashed list is the CI fallback
            for phrase in hashed_hits(line, salt, hashes, max_n):
                findings.append(Finding(path, lineno, "confidential-name", BLOCK,
                                        "banned term (hash match)", excerpt, phrase))
                break

    return findings, suppressed


# --------------------------------------------------------------------------
# Content sources
# --------------------------------------------------------------------------
def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO, capture_output=True,
                          text=True, check=True).stdout


def read_staged(path: str) -> str | None:
    """Read the STAGED blob, not the worktree file.

    Reading the worktree would let someone stage a bad version, fix the file
    locally, and commit the bad blob straight past the gate.
    """
    try:
        out = subprocess.run(["git", "show", f":{path}"], cwd=REPO,
                             capture_output=True, check=True)
        return out.stdout.decode("utf-8")
    except (subprocess.CalledProcessError, UnicodeDecodeError):
        return None


def read_pdf(path: Path) -> str | None:
    """Extract PDF text. Returns None if extraction is impossible."""
    if not shutil.which("pdftotext"):
        return None
    out = subprocess.run(["pdftotext", "-q", str(path), "-"],
                         capture_output=True, text=True)
    return out.stdout if out.returncode == 0 else None


def path_is_denied(rel: str) -> str | None:
    p = Path(rel)
    if p.suffix.lower() in DENY_SUFFIXES:
        return f"data-artifact extension '{p.suffix}' must never be committed"
    if p.name.lower() in DENY_NAMES:
        return f"'{p.name}' is on the never-commit list"
    if re.search(r"(^|/)(index|cases|logs|\.venv|__pycache__)/", rel):
        return f"path '{rel}' looks like generated or case data"
    return None


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Confidentiality gate for the public site repo.")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--all", action="store_true", help="scan every tracked file")
    g.add_argument("--staged", action="store_true", help="scan staged content (default)")
    g.add_argument("--history", action="store_true", help="scan every blob in every commit")
    g.add_argument("--paths", nargs="+", metavar="FILE", help="scan specific files")
    g.add_argument("--stdin", action="store_true", help="scan text from stdin")
    g.add_argument("--self-test", action="store_true", help="verify the gate works")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    salt, hashes, max_n = load_hashed_terms()
    local_terms = load_local_terms()

    if not local_terms and not hashes:
        print("scrub: WARNING no term list found. Confidential-name checks are OFF.\n"
              f"scrub: create {LOCAL_TERMS}, then run tools/make-hashes.py", file=sys.stderr)

    findings: list[Finding] = []
    suppressed = scanned = 0

    if args.stdin:
        text = sys.stdin.read()
        findings, suppressed = scan_text("<stdin>", text, salt, hashes, max_n, local_terms)
        scanned = 1
    elif args.history:
        blobs = set()
        for line in git("rev-list", "--all", "--objects").splitlines():
            parts = line.split(" ", 1)
            if len(parts) == 2 and parts[1].strip():
                blobs.add((parts[0], parts[1].strip()))
        for sha, rel in sorted(blobs):
            if rel in SELF_EXEMPT or Path(rel).suffix.lower() in SKIP_SUFFIXES:
                continue
            try:
                text = subprocess.run(["git", "cat-file", "-p", sha], cwd=REPO,
                                      capture_output=True, check=True).stdout.decode("utf-8")
            except (subprocess.CalledProcessError, UnicodeDecodeError):
                continue
            scanned += 1
            f, s = scan_text(f"{rel}@{sha[:8]}", text, salt, hashes, max_n, local_terms)
            findings.extend(f)
            suppressed += s
    else:
        staged = not (args.all or args.paths)
        if args.paths:
            paths = args.paths
        elif args.all:
            paths = [p for p in git("ls-files").splitlines() if p.strip()]
        else:
            paths = [p for p in git("diff", "--cached", "--name-only",
                                    "--diff-filter=ACMR").splitlines() if p.strip()]

        for rel in paths:
            if rel in SELF_EXEMPT:
                continue
            denied = path_is_denied(rel)
            if denied:
                findings.append(Finding(rel, 0, "forbidden-file", BLOCK, denied, rel))
                continue

            p = Path(rel) if Path(rel).is_absolute() else REPO / rel
            suffix = p.suffix.lower()

            if suffix == ".pdf":
                # PDF text is compressed; grep cannot see it. Fail closed.
                text = read_pdf(p) if p.is_file() else None
                if text is None:
                    findings.append(Finding(rel, 0, "unscannable", BLOCK,
                                            "PDF could not be text-extracted (install poppler: "
                                            "brew install poppler)", rel))
                    continue
            elif suffix in SKIP_SUFFIXES:
                continue
            elif staged:
                text = read_staged(rel)
                if text is None:
                    continue
            else:
                if not p.is_file():
                    continue
                try:
                    text = p.read_text(encoding="utf-8")
                except (UnicodeDecodeError, OSError):
                    continue

            scanned += 1
            f, s = scan_text(rel, text, salt, hashes, max_n, local_terms)
            findings.extend(f)
            suppressed += s

    blocking = [f for f in findings if f.severity == BLOCK]
    warnings = [f for f in findings if f.severity == WARN]
    for f in blocking + warnings:
        print(f.render())

    src = "local plaintext" if local_terms else ("committed hashes" if hashes else "NONE")
    print(f"\nscrub: {scanned} scanned · {len(blocking)} blocking · {len(warnings)} warnings "
          f"· {suppressed} suppressed · terms: {src}")

    if blocking:
        print("\nscrub: BLOCKED. This repo is public. Fix the findings above, or put\n"
              "       `scrub-ok: <reason>` on the line if it is a genuine false positive.")
        return 1
    print("scrub: clean.")
    return 0


def self_test() -> int:
    """Plant one violation per category and assert the gate catches each.

    A gate that has never caught a planted violation is not known to work.
    Every value below is fake. Real values never go in a fixture.
    """
    salt, hashes, max_n = load_hashed_terms()
    local_terms = load_local_terms()

    positives = {
        "credential": "key = 'AKIAIOSFODNN7EXAMPLE'",
        "case-id": "see case 12345678901234567 for detail",
        "arn": "arn:aws:s3:ap-southeast-2:418321941424:bucket/x",
        "internal-host": "docs at https://w.amazon.com/bin/view/Thing",
        "internal-git": "git@ssh.gitlab.aws.dev:someone/tool.git",
        "internal-system": "authenticated through Midway then Dante",
        "personal": "call me on +61 400 000 000 any time",
        "font-license": "font-family: 'Roobert PRO', sans-serif;",
        "account-id": "deployed into account 418321941424",
        "internal-jargon": "passed the assessment with 98%",
    }
    negatives = [
        "read the docs at https://docs.aws.amazon.com/bedrock/",
        "example account 111122223333 per the AWS docs",
        "the SIM card slot is on the left",
        "I lived in Brazil and speak Portuguese",
        "2015-2022 - Seoul, Brazil, Sydney",
        "font-family: -apple-system, 'Segoe UI', sans-serif;",
        "reduced p95 latency by 40% across the fleet",
    ]

    ok = True
    print("planted violations (each must be caught):")
    for category, line in positives.items():
        found, _ = scan_text("selftest", line, salt, hashes, max_n, local_terms)
        hit = any(f.category == category for f in found)
        print(f"  {'PASS' if hit else 'FAIL'}  {category:17} {line[:50]}")
        ok &= hit

    print("\nclean lines (none may block):")
    for line in negatives:
        found, _ = scan_text("selftest", line, salt, hashes, max_n, local_terms)
        bad = [f for f in found if f.severity == BLOCK]
        print(f"  {'PASS' if not bad else 'FAIL'}  {line[:62]}"
              + ("" if not bad else f"\n          spurious: {bad[0].why}"))
        ok &= not bad

    print("\nforbidden paths (each must be refused):")
    for rel in ["index/chunks.jsonl", "catalog.md", "data/index.db", "logs/case.txt"]:
        refused = path_is_denied(rel) is not None
        print(f"  {'PASS' if refused else 'FAIL'}  {rel}")
        ok &= refused

    print("\nallowed paths (none may be refused):")
    for rel in ["index.html", "assets/css/site.css", "resume/index.html", "work/index.html"]:
        refused = path_is_denied(rel) is not None
        print(f"  {'PASS' if not refused else 'FAIL'}  {rel}")
        ok &= not refused

    print("\nsuppression pragma:")
    empty, _ = scan_text("t", "account 418321941424 scrub-ok:", salt, hashes, max_n, local_terms)
    reasoned, _ = scan_text("t", "account 418321941424 scrub-ok: AWS public example",
                            salt, hashes, max_n, local_terms)
    print(f"  {'PASS' if empty else 'FAIL'}  bare `scrub-ok:` with no reason does NOT suppress")
    print(f"  {'PASS' if not reasoned else 'FAIL'}  `scrub-ok: <reason>` does suppress")
    ok &= bool(empty) and not reasoned

    print("\nconfidential-name list:")
    if local_terms or hashes:
        probe = local_terms[0] if local_terms else None
        if probe:
            found, _ = scan_text("t", f"worked with {probe} last quarter",
                                 salt, hashes, max_n, local_terms)
            hit = any(f.category == "confidential-name" for f in found)
            quiet = all(probe.lower() not in f.render().lower() for f in found)
            print(f"  {'PASS' if hit else 'FAIL'}  a term from the list is detected")
            print(f"  {'PASS' if quiet else 'FAIL'}  the matched term is NOT echoed in output")
            ok &= hit and quiet
        else:
            print("  SKIP  hashes present but no plaintext to probe with")
    else:
        print("  SKIP  no term list configured yet")

    print("\nself-test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
