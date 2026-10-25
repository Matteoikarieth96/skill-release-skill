#!/usr/bin/env python3
"""release_scan: find what must not go public before a skill repo is published.

Usage:
  release_scan.py scan PATH [--no-history] [--no-gitleaks] [--json] [--strict] [--config FILE]
  release_scan.py strip FILE [FILE ...] [--force]

scan   Scans a skill folder (the staging copy that becomes the public repo):
       the files that would be committed, every blob in the git history,
       commit messages and identities, gitleaks (when installed), SKILL.md,
       licence, README, SECURITY.md, CI workflows, image / PDF / video /
       office metadata, hidden Unicode, symlinks, and an inventory of risky
       code for the reviewers. Exit 1 if any FAIL (or any WARN with --strict).
strip  Removes metadata from JPEG and PNG files in place (EXIF, XMP, IPTC,
       comments, text chunks, timestamps). Refuses symlinks, and JPEGs whose
       EXIF orientation would be lost, unless --force.

Owner settings: $SKILL_RELEASE_HOME/config.json (default
~/.claude/skill-release/config.json), see templates/config.example.json.
Standard library only, Python 3.9 or newer.
"""
from __future__ import annotations

import argparse
import bisect
import codecs
import fnmatch
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unicodedata
import zipfile
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path

VERSION = "0.1.0"
MAX_TEXT = 2_000_000          # bytes of a text file that are scanned
MAX_MEDIA = 64_000_000        # bytes of a media file that are read
MAX_HISTORY_TOTAL = 300_000_000
WARN_SIZE = 5_000_000
FAIL_SIZE = 50_000_000
SEVERITIES = ("FAIL", "WARN", "INFO")


# ----------------------------------------------------------------- findings

@dataclass
class Finding:
    severity: str
    check: str
    path: str
    line: int
    message: str


class Report:
    """Collects findings, at most CAP of the same kind per file."""

    CAP = 5

    def __init__(self):
        self.findings: list[Finding] = []
        self._counts: dict = {}

    def add(self, severity, check, path, message, line=0):
        key = (severity, check, path)
        n = self._counts.get(key, 0) + 1
        self._counts[key] = n
        if n <= self.CAP:
            self.findings.append(Finding(severity, check, path, line, message))

    def finish(self):
        for (sev, check, path), n in self._counts.items():
            if n > self.CAP:
                self.findings.append(
                    Finding(sev, check, path, 0, f"... and {n - self.CAP} more of the same"))
        order = {s: i for i, s in enumerate(SEVERITIES)}
        self.findings.sort(key=lambda f: (order[f.severity], f.path, f.line, f.check))
        return self

    def count(self, severity):
        return sum(1 for f in self.findings if f.severity == severity)


def mask(secret: str) -> str:
    """First 4 characters, the length and a short fingerprint that tells two secrets apart."""
    secret = secret.strip()
    tag = hashlib.sha256(secret.encode("utf-8", "replace")).hexdigest()[:6]
    return f"{secret[:4]}...({len(secret)} chars, #{tag})"


def clean(value, limit=80) -> str:
    """Printable, single-line, truncated version of an untrusted string."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    value = "".join(ch if ch.isprintable() else "?" for ch in str(value))
    return value if len(value) <= limit else value[:limit] + "..."


_LINES: list = [None, []]


def line_of(text: str, pos: int) -> int:
    """1-based line of a position; newline offsets are cached for the text being scanned."""
    if _LINES[0] is not text:
        _LINES[0] = text
        _LINES[1] = [m.start() for m in re.finditer("\n", text)]
    return bisect.bisect_left(_LINES[1], pos) + 1


# ------------------------------------------------------------------- config

DEFAULT_CONFIG = {
    "github_owner": "",
    "copyright_holder": "",
    "author_identities": [],
    "allowed_emails": [],
    "private_terms_file": "",
    "private_terms": [],
    "banned_text": [],
    "require_intake": False,
}


def local_home() -> Path:
    env = os.environ.get("SKILL_RELEASE_HOME")
    return Path(env).expanduser() if env else Path.home() / ".claude" / "skill-release"


def load_config(path=None) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    cfg_path = Path(path).expanduser() if path else local_home() / "config.json"
    source = ""
    if cfg_path.is_file():
        try:
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise SystemExit(f"config is not valid JSON: {cfg_path}: {exc}")
        if not isinstance(data, dict):
            raise SystemExit(f"config must be a JSON object: {cfg_path}")
        cfg.update(data)
        source = str(cfg_path)
    elif path:
        raise SystemExit(f"config not found: {cfg_path}")
    for key in ("author_identities", "allowed_emails", "private_terms", "banned_text"):
        if not isinstance(cfg.get(key), list) or not all(isinstance(x, str) for x in cfg[key]):
            raise SystemExit(f"config key {key!r} must be a list of strings")
    terms = list(cfg["private_terms"])
    terms_file = cfg.get("private_terms_file") or "private-terms.txt"
    tf = Path(os.path.expanduser(str(terms_file)))
    if not tf.is_absolute():
        tf = cfg_path.parent / tf
    if tf.is_file():
        for raw in tf.read_text(encoding="utf-8").splitlines():
            term = raw.strip()
            if term and not term.startswith("#"):
                terms.append(term)
    cfg["_terms"] = sorted({t for t in terms if t}, key=lambda t: (-len(t), t.lower()))
    cfg["_terms_re"] = _terms_regex(cfg["_terms"])
    # Bytes of binary files hit short terms by chance: only terms of 5+ characters there.
    cfg["_terms_re_long"] = _terms_regex([t for t in cfg["_terms"] if len(t) >= 5])
    cfg["_source"] = source
    cfg["_terms_file"] = str(tf) if tf.is_file() else ""
    return cfg


def _terms_regex(terms):
    if not terms:
        return None
    parts = []
    for t in terms:
        p = re.escape(t)
        if t[0].isalnum():
            p = r"(?<![A-Za-z0-9])" + p
        if t[-1].isalnum():
            p = p + r"(?![A-Za-z0-9])"
        parts.append(p)
    return re.compile("|".join(parts), re.IGNORECASE)


# -------------------------------------------------------------- text rules

PLACEHOLDER_HINTS = (
    "your", "xxx", "example", "changeme", "change_me", "placeholder", "dummy",
    "fake", "redacted", "sample", "<", ">", "${", "{{", "%s", "...", "***",
    "os.environ", "getenv", "process.env", "env[", "replace", "todo", "insert",
    "password", "passw0rd", "secret_here", "none", "null",
)


def is_placeholder(value: str) -> bool:
    v = value.lower()
    if len(set(v)) <= 2:
        return True
    if re.fullmatch(r"\{[^{}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|%\([a-z_]+\)s", value):
        return True
    return any(h in v for h in PLACEHOLDER_HINTS)


SECRET_RULES = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("github-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("api-key-sk", re.compile(r"\bsk-(?:proj-|or-v1-|live-)?[A-Za-z0-9_-]{32,}")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("stripe-live-key", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{16,}")),
    ("telegram-bot-token", re.compile(r"\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b")),
    ("private-key-block", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]
URL_CREDENTIALS = re.compile(
    r"\b[a-z][a-z0-9+.-]{1,20}://([^\s:/@'\"<>]{1,64}):([^\s@/'\"<>]{3,128})@[A-Za-z0-9.-]+")
GENERIC_SECRET = re.compile(
    r"(?i)\b(api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token"
    r"|token|secret|passw(?:or)?d|passwd|pwd)\b[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,200})[\"']")
ARDUINO_SECRET = re.compile(r"#define\s+(SECRET_[A-Z0-9_]+)\s+\"([^\"]*)\"")
WIFI_ASSIGN = re.compile(
    r"(?i)\b(?:wifi|wlan|ssid)[_-]?(?:pass(?:word)?|pwd|psk|key)\b\s*[:=]\s*[\"']([^\"']{4,})[\"']")
WIFI_BEGIN = re.compile(r"WiFi\.begin\(\s*\"([^\"]+)\"\s*,\s*\"([^\"]+)\"")
CRYPTO_KEY_LINE = re.compile(r"(?i)(private[_ -]?key|priv[_-]?key|secret[_-]?key|wallet[_-]?key)")
HEX64 = re.compile(r"\b(?:0x)?[0-9a-fA-F]{64}\b")
MNEMONIC = re.compile(
    r"(?i)(?:mnemonic|seed[ _-]?phrase|recovery[ _-]?phrase)\W{0,12}((?:[a-z]{3,8}\s+){11,23}[a-z]{3,8})")

EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]{1,64})@"
    r"([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.([A-Za-z]{2,24}))(?![A-Za-z0-9-])")
FILE_EXT_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "js", "mjs", "css", "json", "md",
                 "html", "py", "txt", "ts", "tsx", "wasm", "map", "pdf", "mp4", "mov"}
SAFE_EMAIL_DOMAINS = ("example.com", "example.org", "example.net", "users.noreply.github.com",
                      "localhost")
SAFE_EMAIL_SUFFIXES = (".example", ".test", ".invalid", ".localhost", ".example.com",
                       ".example.org", ".example.net")
PHONE = re.compile(r"(?<![\w+])\+\d[\d .-]{7,17}\d(?![\d])")
IBAN = re.compile(r"\b([A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?)\b")
CODICE_FISCALE = re.compile(r"\b[A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b")
CARD = re.compile(r"(?<![\d.])(?:[3-6]\d{14,15}|(?:\d{4}[ -]){3}\d{1,7})(?![\d.])")
TEST_CARDS = {"4242424242424242", "4111111111111111", "5555555555554444", "4000056655665556",
              "378282246310005", "6011111111111117"}
PRIVATE_IP = re.compile(
    r"(?<![\d.])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])")
MAC_ADDR = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
# A root-level /Users/<name> or /home/<name>, not a subfolder called "home".
HOME_PATH = re.compile(r"(?<![\w}\]).~-])(?:/Users/|/home/)([A-Za-z0-9_][A-Za-z0-9._-]{0,63})")
WIN_HOME = re.compile(r"[A-Za-z]:\\+Users\\+([A-Za-z0-9._-]{1,64})")
PLACEHOLDER_USERS = {"shared", "you", "user", "username", "name", "me", "runner", "example",
                     "yourname", "your-name", "your_name", "alice", "bob", "someone", "jdoe"}
AUTHOR_MACHINE = re.compile(
    r"~/(?:Desktop|Documents|Downloads|Library/(?:Mobile Documents|CloudStorage))\b")
USB_SERIAL = re.compile(
    r"/dev/(?:cu|tty)\.(?:usbmodem|usbserial|SLAB_USBtoUART|wchusbserial)[-_]?([A-Za-z0-9]{4,})")
LOCAL_HOST = re.compile(r"(?<![.\w-])([A-Za-z0-9-]{3,63})\.local\b(?!\.[A-Za-z])")
CURL_PIPE_SHELL = re.compile(r"(?:curl|wget)[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b")
PLACEHOLDER_LEFT = re.compile(r"\{\{[A-Z][A-Z0-9_]*\}\}")
NON_PLAIN = re.compile(r"[^\x09\x0a\x0d\x20-\x7e]")
INVISIBLE_EXTRA = {0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800, 0x180E}
GITLEAKS_ALLOW = "gitleaks" + ":allow"
CONFIG_EXT = {"", ".env", ".envrc", ".ini", ".cfg", ".conf", ".properties", ".toml", ".yaml", ".yml",
              ".txt", ".sh", ".bash", ".zsh"}
GENERIC_UNQUOTED = re.compile(
    r"(?im)^[ \t]*(?:export[ \t]+)?([A-Z0-9_.-]{0,40}(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY)"
    r"[A-Z0-9_.-]{0,40})[ \t]*[=:][ \t]*([^\s\"'#]{8,200})[ \t]*$")


def _emoji_base(ch: str) -> bool:
    return unicodedata.category(ch) in ("So", "Sm", "Sk", "No") or ch in "0123456789#*\ufe0f"


def hidden_chars(text: str):
    """Yields (position, codepoint, severity) for characters that can hide or reorder text.

    FAIL: format characters (bidi controls, zero-width, tags), line and paragraph
    separators, variation selectors outside an emoji, invisible fillers, ESC and
    C1 controls. WARN: other C0 controls, private-use and unassigned characters.
    "BOM": a byte order mark at the very start.
    """
    n = len(text)
    for m in NON_PLAIN.finditer(text):
        i = m.start()
        ch = m.group(0)
        cp = ord(ch)
        if cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F:
            yield i, cp, ("FAIL" if cp == 0x1B or cp >= 0x80 else "WARN")
            continue
        if cp == 0xFEFF and i == 0:
            yield i, cp, "BOM"
            continue
        prev = text[i - 1] if i else ""
        nxt = text[i + 1] if i + 1 < n else ""
        if cp in (0xFE0E, 0xFE0F):
            if prev and prev not in "\ufe0e\ufe0f" and _emoji_base(prev) and nxt not in ("\ufe0e", "\ufe0f"):
                continue
            yield i, cp, "FAIL"
            continue
        if cp == 0x200D and prev and nxt and _emoji_base(prev) and _emoji_base(nxt):
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cf", "Zl", "Zp") or cp in INVISIBLE_EXTRA or 0xFE00 <= cp <= 0xFE0F \
                or 0xE0100 <= cp <= 0xE01EF:
            yield i, cp, "FAIL"
        elif cat in ("Co", "Cn"):
            yield i, cp, "WARN"


def html_comments(text: str):
    """(position, body) of each HTML comment, found without backtracking."""
    i = text.find("<!--")
    while i != -1:
        j = text.find("-->", i + 4)
        if j == -1:
            yield i, text[i + 4:i + 200]
            return
        yield i, text[i + 4:j]
        i = text.find("<!--", j + 3)


MEMORY_MARKER = "origin" + "SessionId"
TRANSCRIPT_MARKER = re.compile(r"\"session" + r"Id\"\s*:")

CODE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".zsh",
            ".html", ".htm", ".rb", ".go", ".rs", ".ino", ".cpp", ".c", ".h", ".hpp",
            ".ps1", ".php", ".swift", ".pl"}
CODE_RULES = [
    ("WARN", "shell-true", re.compile(r"shell\s*=\s*True"),
     "subprocess run through the shell: injection risk if any part comes from input"),
    ("WARN", "eval-exec", re.compile(r"(?<![\w.])(?:eval|exec)\s*\("),
     "eval/exec: make sure the input can never come from a user or a file"),
    ("WARN", "pickle-load", re.compile(r"\bpickle\.loads?\s*\("), "pickle load is unsafe on untrusted files"),
    ("WARN", "yaml-load", re.compile(r"\byaml\.load\s*\((?![^)\n]*Loader\s*=\s*yaml\.SafeLoader)"),
     "yaml.load without SafeLoader"),
    ("WARN", "bind-all", re.compile(r"0\.0\.0\.0"),
     "all-interfaces address: a local server bound there is reachable from the whole network"),
    ("WARN", "chmod-777", re.compile(r"chmod\s+(?:-R\s+)?0?777"), "world-writable permissions"),
    # Some words are split so that this file does not match its own rules.
    ("WARN", "tls-off", re.compile(
        r"verify\s*=\s*False|CERT_" r"NONE|rejectUnauthorized\s*:\s*false|--in" r"secure\b"
        r"|NODE_TLS_REJECT_" r"UNAUTHORIZED"), "TLS verification turned off"),
    ("INFO", "runs-commands", re.compile(
        r"\bsubprocess\.|\bos\.system\s*\(|\bos\.popen\s*\(|\bchild_process\b|\bexecSync\s*\("),
     "runs external commands"),
    ("INFO", "network", re.compile(
        r"\burllib\.request\b|\bhttp\.client\b|\brequests\.(?:get|post|put|delete|request)\b"
        r"|\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\s*\(|\bsocket\.socket\s*\("),
     "network access"),
    ("INFO", "html-from-strings", re.compile(
        r"\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|document\.write\s*\("),
     "builds HTML from strings: check escaping"),
    ("INFO", "recursive-delete", re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f|\bshutil\.rmtree\s*\("),
     "recursive delete"),
    ("INFO", "sudo", re.compile(r"\bsudo\s"), "uses sudo"),
]
SCRIPT_SRC = re.compile(r"<script\b[^>]{0,2000}\bsrc[ \t]*=[ \t]*[\"']https?://[^\"'\s>]{1,1000}[\"'][^>]{0,2000}>", re.I)


def iban_valid(raw: str) -> bool:
    s = raw.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    s = s[4:] + s[:4]
    digits = "".join(str(int(ch, 36)) for ch in s)
    return int(digits) % 97 == 1


def luhn_valid(num: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(num)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


PUBLIC_SERVICE_EMAILS = {"support@github.com", "noreply@github.com"}
PLATFORM_IDENTITY = re.compile(
    r"^(?:GitHub <noreply@github\.com>|[^<>]*\[bot\] <[^<>]*\[bot\]@users\.noreply\.github\.com>)$")


def email_allowed(local: str, domain: str, tld: str, cfg) -> bool:
    l, d = local.lower(), domain.lower()
    if f"{l}@{d}" in {e.lower() for e in cfg["allowed_emails"]} | PUBLIC_SERVICE_EMAILS:
        return True
    if tld.lower() in FILE_EXT_TLDS:
        return True
    if d in SAFE_EMAIL_DOMAINS or d.endswith(SAFE_EMAIL_SUFFIXES):
        return True
    if l == "git" and d in ("github.com", "gitlab.com", "bitbucket.org"):
        return True
    return "noreply" in l or "no-reply" in l


PLACEHOLDER_LOGINS = {"user", "username", "login", "name", "admin", "pass", "pwd", "pw"}


def scan_text(text: str, path: str, rep: Report, cfg, *, ext: str = "", origin: str = "",
              full: bool = True, leak_only: bool = False, binary: bool = False):
    """Content rules for one text: a file, a history blob or a commit message.

    full=False (history, commit messages, document parts) keeps the leak and
    personal-data rules and drops the style, inventory and code rules.
    leak_only=True (bytes of binary files read as latin-1) keeps only the FAIL
    rules for secrets, private terms and Claude files.
    """
    where = f"{path} ({origin})" if origin else path
    covered: list = []

    def fail_secret(check, m, value=None):
        for a, b in covered:
            if a <= m.start() < b:
                return
        covered.append((m.start(), m.end()))
        rep.add("FAIL", check, where, f"possible secret {mask(value or m.group(0))}",
                line_of(text, m.start()))

    for check, rx in SECRET_RULES:
        for m in rx.finditer(text):
            fail_secret(check, m)
    for m in URL_CREDENTIALS.finditer(text):
        pwd = m.group(2)
        if not is_placeholder(pwd) and pwd.lower() not in PLACEHOLDER_LOGINS:
            fail_secret("url-credentials", m, pwd)
    for m in ARDUINO_SECRET.finditer(text):
        if m.group(2) and not is_placeholder(m.group(2)):
            rep.add("FAIL", "arduino-secret", where,
                    f"{m.group(1)} has a real-looking value {mask(m.group(2))}: ship an empty template",
                    line_of(text, m.start()))
    for m in WIFI_ASSIGN.finditer(text):
        if not is_placeholder(m.group(1)):
            rep.add("FAIL", "wifi-password", where, f"Wi-Fi password {mask(m.group(1))}",
                    line_of(text, m.start()))
    for m in WIFI_BEGIN.finditer(text):
        if not is_placeholder(m.group(2)):
            rep.add("FAIL", "wifi-password", where,
                    f"WiFi.begin with a literal password {mask(m.group(2))}", line_of(text, m.start()))
    for m in HEX64.finditer(text):
        start = text.rfind("\n", 0, m.start()) + 1
        end = text.find("\n", m.end())
        line = text[start:end if end != -1 else len(text)][:2000]
        if CRYPTO_KEY_LINE.search(line):
            rep.add("FAIL", "crypto-private-key", where,
                    f"64-hex value next to a key word {mask(m.group(0))}", line_of(text, m.start()))
    for m in MNEMONIC.finditer(text):
        rep.add("FAIL", "seed-phrase", where, "looks like a wallet seed phrase",
                line_of(text, m.start()))

    terms_rx = cfg.get("_terms_re_long" if binary else "_terms_re")
    if terms_rx:
        for m in terms_rx.finditer(text):
            rep.add("FAIL", "private-term", where, f"private term {clean(m.group(0), 40)!r}",
                    line_of(text, m.start()))

    if MEMORY_MARKER in text:
        rep.add("FAIL", "claude-memory", where, "looks like a Claude memory file")
    if ext == ".jsonl" and TRANSCRIPT_MARKER.search(text):
        rep.add("FAIL", "claude-transcript", where, "looks like a Claude session transcript")
    if leak_only:
        return

    for m in GENERIC_SECRET.finditer(text):
        val = m.group(2)
        if is_placeholder(val) or any(a <= m.start(2) < b for a, b in covered):
            continue
        rep.add("WARN", "secret-assignment", where,
                f"{m.group(1)} assigned a literal {mask(val)}: confirm it is not real",
                line_of(text, m.start()))
    base = path.rsplit("/", 1)[-1].lower()
    config_like = ext in CONFIG_EXT or base.startswith((".env", "env."))
    for m in (GENERIC_UNQUOTED.finditer(text) if config_like else ()):
        val = m.group(2)
        if is_placeholder(val) or any(a <= m.start(2) < b for a, b in covered):
            continue
        rep.add("WARN", "secret-assignment", where,
                f"{clean(m.group(1), 40)} set to an unquoted literal {mask(val)}: confirm it is not real",
                line_of(text, m.start()))

    for m in EMAIL.finditer(text):
        if any(a <= m.start() < b for a, b in covered):
            continue
        if not email_allowed(m.group(1), m.group(2), m.group(3), cfg):
            rep.add("WARN", "email", where,
                    f"email address {clean(m.group(1)[:2], 4)}...@{clean(m.group(2), 50)}",
                    line_of(text, m.start()))
    for m in PHONE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 9 <= len(digits) <= 15:
            rep.add("WARN", "phone", where, f"phone number {mask(digits)}",
                    line_of(text, m.start()))
    for m in IBAN.finditer(text):
        if iban_valid(m.group(1)):
            rep.add("FAIL", "iban", where, f"valid IBAN {mask(m.group(1))}", line_of(text, m.start()))
    for m in CODICE_FISCALE.finditer(text):
        rep.add("WARN", "tax-code", where, f"Italian tax code {mask(m.group(0))}",
                line_of(text, m.start()))
    for m in CARD.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and len(set(digits)) > 2 and luhn_valid(digits) \
                and digits not in TEST_CARDS:
            rep.add("WARN", "card-number", where, f"passes the card checksum {mask(digits)}",
                    line_of(text, m.start()))
    for m in PRIVATE_IP.finditer(text):
        rep.add("WARN", "private-ip", where, f"private network address {m.group(1)}",
                line_of(text, m.start()))
    for m in MAC_ADDR.finditer(text):
        rep.add("WARN", "mac-address", where, f"hardware address {m.group(0)}",
                line_of(text, m.start()))
    for rx in (HOME_PATH, WIN_HOME):
        for m in rx.finditer(text):
            if m.group(1).lower() not in PLACEHOLDER_USERS:
                rep.add("WARN", "home-path", where,
                        f"home folder path reveals a user name ({clean(m.group(0), 40)})",
                        line_of(text, m.start()))
    for m in AUTHOR_MACHINE.finditer(text):
        rep.add("WARN", "author-machine-path", where,
                f"path that only exists on the author's machine ({m.group(0)})",
                line_of(text, m.start()))
    for m in USB_SERIAL.finditer(text):
        rep.add("WARN", "device-serial", where,
                f"serial port name carries a device serial ({clean(m.group(0), 50)})",
                line_of(text, m.start()))
    for m in LOCAL_HOST.finditer(text):
        rep.add("WARN", "local-hostname", where, f"local host name {clean(m.group(0), 50)}",
                line_of(text, m.start()))

    for pos, cp, sev in hidden_chars(text):
        if sev == "BOM":
            if full:
                rep.add("WARN", "bom", where, "file starts with a byte order mark")
            continue
        if sev == "WARN" and not full:
            continue
        rep.add(sev, "hidden-unicode", where,
                f"invisible, control or direction-changing character U+{cp:04X}: "
                "can hide text from reviewers", line_of(text, pos))
    if not full:
        return
    for m in CURL_PIPE_SHELL.finditer(text):
        rep.add("WARN", "curl-pipe-shell", where,
                "download piped into a shell: never run it on the reviewer's machine",
                line_of(text, m.start()))
    idx = text.find(GITLEAKS_ALLOW)
    if idx != -1:
        rep.add("WARN", "gitleaks-allow", where,
                "inline gitleaks allow-comment: it silences gitleaks elsewhere (this scan ignores it)",
                line_of(text, idx))
    if ext == ".md":
        for pos, body in html_comments(text):
            rep.add("INFO", "hidden-comment", where,
                    f"HTML comment, not shown when rendered: {clean(body.strip(), 60)!r}",
                    line_of(text, pos))
    for banned in cfg["banned_text"]:
        idx = text.find(banned)
        while idx != -1:
            rep.add("WARN", "banned-text", where, f"banned text {banned!r}", line_of(text, idx))
            idx = text.find(banned, idx + len(banned))

    if ext in CODE_EXT:
        for sev, check, rx, msg in CODE_RULES:
            hits = list(rx.finditer(text))
            if hits:
                more = f" ({len(hits)} places)" if len(hits) > 1 else ""
                rep.add(sev, check, where, msg + more, line_of(text, hits[0].start()))
    if ext in (".html", ".htm"):
        for m in SCRIPT_SRC.finditer(text):
            if "integrity=" not in m.group(0).lower():
                rep.add("WARN", "cdn-without-sri", where,
                        f"external script without Subresource Integrity: {clean(m.group(0), 70)}",
                        line_of(text, m.start()))


# -------------------------------------------------------------- media rules

TIFF_TAGS = {
    0x010F: "Make", 0x0110: "Model", 0x0131: "Software", 0x013B: "Artist",
    0x8298: "Copyright", 0x0132: "DateTime", 0x010E: "ImageDescription",
    0x9003: "DateTimeOriginal", 0xA430: "CameraOwnerName", 0xA431: "BodySerialNumber",
    0xA435: "LensSerialNumber", 0x9C9B: "XPTitle", 0x9C9C: "XPComment",
    0x9C9D: "XPAuthor", 0x9C9F: "XPSubject", 0x927C: "MakerNote",
}


def parse_tiff(buf: bytes) -> dict:
    """Reads IFD0, the Exif IFD and the GPS IFD. Returns {} on anything malformed."""
    if len(buf) < 8 or buf[:2] not in (b"II", b"MM"):
        return {}
    e = "<" if buf[:2] == b"II" else ">"
    try:
        if struct.unpack(e + "H", buf[2:4])[0] != 42:
            return {}
        first = struct.unpack(e + "I", buf[4:8])[0]
    except struct.error:
        return {}

    def read_ifd(off):
        out = {}
        if off <= 0 or off + 2 > len(buf):
            return out
        n = struct.unpack(e + "H", buf[off:off + 2])[0]
        if n > 1000:
            return out
        for i in range(n):
            p = off + 2 + 12 * i
            if p + 12 > len(buf):
                break
            tag, typ, count = struct.unpack(e + "HHI", buf[p:p + 8])
            raw = buf[p + 8:p + 12]
            if typ == 2:
                data = raw[:count] if count <= 4 else buf[struct.unpack(e + "I", raw)[0]:][:min(count, 512)]
                out[tag] = data.split(b"\0")[0].decode("latin-1", "replace")
            elif typ == 3 and count == 1:
                out[tag] = struct.unpack(e + "H", raw[:2])[0]
            elif typ in (4, 13) and count == 1:
                out[tag] = struct.unpack(e + "I", raw)[0]
            elif typ in (1, 7) and tag in (0x9C9B, 0x9C9C, 0x9C9D, 0x9C9F):
                start = struct.unpack(e + "I", raw)[0] if count > 4 else None
                data = raw[:count] if start is None else buf[start:start + min(count, 512)]
                out[tag] = data.decode("utf-16-le", "replace").split("\0")[0]
            else:
                out[tag] = True
        return out

    ifd0 = read_ifd(first)
    result = {"ifd0": ifd0, "exif": {}, "gps": {}}
    if isinstance(ifd0.get(0x8769), int) and ifd0.get(0x8769) is not True:
        result["exif"] = read_ifd(ifd0[0x8769])
    if 0x8825 in ifd0:
        ptr = ifd0[0x8825]
        result["gps"] = read_ifd(ptr) if isinstance(ptr, int) and ptr is not True else {"?": True}
        result["gps_pointer"] = True
    return result


def report_tiff(info: dict, where: str, rep: Report, cfg):
    if not info:
        return
    if info.get("gps_pointer"):
        gps = {k: v for k, v in info["gps"].items() if k != 0}
        if gps:
            rep.add("FAIL", "gps-location", where, "EXIF GPS location: strip it before publishing")
        else:
            rep.add("WARN", "gps-location", where, "EXIF GPS block present (no coordinates found)")
    texts = []
    for block in ("ifd0", "exif"):
        for tag, val in info.get(block, {}).items():
            name = TIFF_TAGS.get(tag)
            if not name:
                continue
            shown = clean(val, 50) if isinstance(val, str) else "present"
            rep.add("WARN", "photo-metadata", where, f"EXIF {name}: {shown}")
            if isinstance(val, str):
                texts.append(val)
    _terms_in_strings(texts, where, rep, cfg)


def _terms_in_strings(texts, where, rep, cfg):
    rx = cfg.get("_terms_re")
    if not rx:
        return
    for t in texts:
        for m in rx.finditer(t):
            rep.add("FAIL", "private-term", where, f"private term {clean(m.group(0), 40)!r} in metadata")


def jpeg_walk(data: bytes):
    """Every marker segment of a JPEG, also between and after the scans, up to EOI.

    Yields (marker, start, end, payload). Entropy-coded scan data is skipped by
    looking for the next real marker (FF followed by anything but 00, RSTn, FF).
    """
    if data[:2] != b"\xff\xd8":
        return
    n = len(data)
    i = 2
    in_scan = False
    while i < n:
        if in_scan:
            j = data.find(b"\xff", i)
            if j == -1:
                return
            k = j + 1
            while k < n and data[k] == 0xFF:
                k += 1
            if k >= n:
                return
            if data[k] == 0x00 or 0xD0 <= data[k] <= 0xD7:
                i = k + 1
                continue
            i = k - 1
            in_scan = False
        if data[i] != 0xFF:
            return
        while i < n and data[i] == 0xFF:
            i += 1
        if i >= n:
            return
        marker = data[i]
        start = i - 1
        i += 1
        if marker == 0x01 or 0xD0 <= marker <= 0xD8:
            continue
        if marker == 0xD9:
            yield marker, start, i, b""
            return
        if i + 2 > n:
            return
        seglen = struct.unpack(">H", data[i:i + 2])[0]
        if seglen < 2 or i + seglen > n:
            return
        yield marker, start, i + seglen, data[i + 2:i + seglen]
        i += seglen
        if marker == 0xDA:
            in_scan = True


jpeg_segments = jpeg_walk


def jpeg_orientation(data: bytes):
    for marker, _s, _e, payload in jpeg_walk(data):
        if marker == 0xE1 and payload.startswith(b"Exif\0\0"):
            return parse_tiff(payload[6:]).get("ifd0", {}).get(0x0112)
    return None


XMP_HEADERS = (b"ns.adobe.com/xap", b"ns.adobe.com/xmp/extension")


def iptc_size(payload: bytes) -> int:
    """Size of the IPTC resource (8BIM 0x0404) in a Photoshop APP13 block, 0 if absent or empty."""
    i = payload.find(b"8BIM\x04\x04")
    if i == -1 or i + 7 > len(payload):
        return 0
    name_len = payload[i + 6]
    j = i + 6 + ((1 + name_len + 1) & ~1)
    if j + 4 > len(payload):
        return 1
    return struct.unpack(">I", payload[j:j + 4])[0]


def scan_jpeg(data, where, rep, cfg):
    exif_at, xmp_ranges, eoi = set(), [], None
    for marker, start, end, payload in jpeg_walk(data):
        if marker == 0xD9:
            eoi = end
        elif marker == 0xE1 and payload.startswith(b"Exif\0\0"):
            exif_at.add(start + 4)
            report_tiff(parse_tiff(payload[6:]), where, rep, cfg)
        elif marker == 0xE1 and any(h in payload[:80] for h in XMP_HEADERS):
            xmp_ranges.append((start, end))
            _xmp(payload, where, rep, cfg)
        elif marker == 0xED:
            if iptc_size(payload) > 0:
                rep.add("WARN", "photo-metadata", where,
                        "IPTC block (APP13): can hold author, caption and place fields")
                _terms_in_strings([payload.decode("latin-1")], where, rep, cfg)
            else:
                rep.add("INFO", "photo-metadata", where, "Photoshop block (APP13) with no IPTC data")
        elif marker == 0xFE:
            rep.add("WARN", "photo-metadata", where, f"JPEG comment: {clean(payload, 50)!r}")
        elif 0xE3 <= marker <= 0xEF and marker != 0xEE:
            rep.add("INFO", "photo-metadata", where, f"APP{marker - 0xE0} block: strip removes it")
    pos = data.find(b"Exif\0\0")
    while pos != -1:
        if pos not in exif_at:
            rep.add("WARN", "photo-metadata", where, "Exif block outside the image header")
            report_tiff(parse_tiff(data[pos + 6:pos + 6 + 65536]), where, rep, cfg)
        pos = data.find(b"Exif\0\0", pos + 1)
    pos = data.find(b"<x:xmpmeta")
    while pos != -1:
        if not any(a <= pos < b for a, b in xmp_ranges):
            rep.add("WARN", "photo-metadata", where, "XMP block outside the image header")
            _xmp(data[pos:pos + 262144], where, rep, cfg)
        pos = data.find(b"<x:xmpmeta", pos + 1)
    if eoi is None:
        rep.add("WARN", "photo-metadata", where, "no end-of-image marker: truncated or not a plain JPEG")
    elif eoi < len(data):
        rep.add("WARN", "photo-metadata", where,
                f"{len(data) - eoi} bytes after the end of the image: strip removes them")


def _xmp(payload: bytes, where, rep, cfg):
    text = payload.decode("utf-8", "replace")
    if re.search(r"GPS(?:Latitude|Longitude)", text):
        rep.add("FAIL", "gps-location", where, "XMP GPS location: strip it before publishing")
    names = re.findall(r"<(dc:creator|xmp:CreatorTool|photoshop:AuthorsPosition|exif:\w{1,40})", text)
    rep.add("WARN", "photo-metadata", where,
            "XMP metadata block" + (f" ({', '.join(sorted(set(names)))[:80]})" if names else ""))
    _terms_in_strings([text], where, rep, cfg)


PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_SAFE = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"cHRM", b"gAMA", b"iCCP", b"sBIT",
            b"sRGB", b"bKGD", b"hIST", b"pHYs", b"sPLT", b"acTL", b"fcTL", b"fdAT", b"cICP",
            b"mDCv", b"cLLi"}


def png_chunks(data: bytes):
    if data[:8] != PNG_SIG:
        return
    i = 8
    while i + 12 <= len(data):
        length = struct.unpack(">I", data[i:i + 4])[0]
        ctype = data[i + 4:i + 8]
        end = i + 12 + length
        if end > len(data):
            return
        yield ctype, i, end, data[i + 8:i + 8 + length]
        if ctype == b"IEND":
            return
        i = end


def _inflate(blob: bytes, limit=1_000_000) -> bytes:
    try:
        return zlib.decompressobj().decompress(blob, limit)
    except zlib.error:
        return b""


def scan_png(data, where, rep, cfg):
    end = None
    for ctype, _s, cend, payload in png_chunks(data):
        if ctype == b"IEND":
            end = cend
        elif ctype == b"tEXt":
            key, _, val = payload.partition(b"\0")
            _png_text(key, val, where, rep, cfg)
        elif ctype == b"zTXt":
            key, _, rest = payload.partition(b"\0")
            _png_text(key, _inflate(rest[1:]), where, rep, cfg)
        elif ctype == b"iTXt":
            key, _, rest = payload.partition(b"\0")
            if len(rest) >= 2:
                flag, body = rest[0], rest[2:]
                body = body.split(b"\0", 2)[-1] if body.count(b"\0") >= 2 else body
                _png_text(key, _inflate(body) if flag else body, where, rep, cfg)
        elif ctype == b"eXIf":
            report_tiff(parse_tiff(payload), where, rep, cfg)
        elif ctype == b"tIME":
            rep.add("INFO", "photo-metadata", where, "PNG modification time chunk")
        elif ctype not in PNG_SAFE:
            rep.add("WARN", "photo-metadata", where,
                    f"PNG chunk {clean(ctype, 8)!r}: private or unknown data, strip removes it")
            _terms_in_strings([payload[:MAX_TEXT].decode("latin-1")], where, rep, cfg)
    if end is None:
        rep.add("WARN", "photo-metadata", where, "no IEND chunk: truncated PNG")
    elif end < len(data):
        rep.add("WARN", "photo-metadata", where,
                f"{len(data) - end} bytes after the end of the image: strip removes them")


def _png_text(key: bytes, val: bytes, where, rep, cfg):
    k = clean(key, 30)
    text = val.decode("utf-8", "replace")
    if k == "XML:com.adobe.xmp" or "ns.adobe.com/xap" in text[:200]:
        _xmp(val, where, rep, cfg)
        return
    rep.add("WARN", "photo-metadata", where, f"PNG text {k}: {clean(text, 50)!r}")
    _terms_in_strings([text], where, rep, cfg)


PDF_INFO = re.compile(r"/(Author|Creator|Producer|Title|Subject|Keywords)\s*\(([^)]{0,200})\)")
PDF_INFO_HEX = re.compile(r"/(Author|Creator|Producer|Title|Subject|Keywords)\s*<([0-9A-Fa-f\s]{2,1000})>")
PDF_STREAM = re.compile(rb"(?<!end)stream\r?\n")


def _pdf_hex(value: str) -> str:
    hexs = re.sub(r"\s", "", value)
    if len(hexs) % 2:
        hexs += "0"
    raw = bytes.fromhex(hexs)
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", "replace")
    return raw.decode("latin-1")


def scan_pdf(data, where, rep, cfg):
    text = data.decode("latin-1")
    for rx, decode in ((PDF_INFO, lambda v: v), (PDF_INFO_HEX, _pdf_hex)):
        for m in rx.finditer(text):
            value = decode(m.group(2))
            sev = "INFO" if m.group(1) == "Producer" else "WARN"
            rep.add(sev, "pdf-metadata", where, f"PDF {m.group(1)}: {clean(value, 50)!r}")
            _terms_in_strings([value], where, rep, cfg)
    if "<x:xmpmeta" in text:
        rep.add("WARN", "pdf-metadata", where, "PDF has an XMP metadata packet")
    _terms_in_strings([text], where, rep, cfg)
    total = 0
    for m in PDF_STREAM.finditer(data):
        stop = data.find(b"endstream", m.end())
        if stop == -1:
            break
        inflated = _inflate(data[m.end():stop], 5_000_000)
        if not inflated:
            continue
        total += len(inflated)
        if total > 40_000_000:
            rep.add("WARN", "pdf-metadata", where, "PDF streams only partly scanned (size cap)")
            break
        scan_text(inflated.decode("latin-1"), where, rep, cfg, origin="pdf stream", leak_only=True)


def scan_video(data, where, rep, cfg):
    if b"\xa9xyz" in data or b"com.apple.quicktime.location" in data:
        rep.add("FAIL", "gps-location", where, "video has a recording location: strip it (ffmpeg -map_metadata -1)")
    for tag, label in ((b"com.apple.quicktime.make", "device make"), (b"\xa9mak", "device make"),
                       (b"\xa9mod", "device model"), (b"com.apple.quicktime.model", "device model")):
        if tag in data:
            rep.add("WARN", "video-metadata", where, f"video metadata: {label}")


OFFICE_EXTS = (".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".odt", ".ods", ".odp")
PART_CAP = 5_000_000
DOC_TOTAL_CAP = 40_000_000


def scan_zip(data, where, rep, cfg, name):
    import io
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except Exception:
        rep.add("FAIL", "archive", where, "unreadable zip-based file: remove it or export it again")
        return
    names = {i.filename for i in infos}
    office = "[Content_Types].xml" in names or "mimetype" in names or name.endswith(OFFICE_EXTS)
    if not office:
        rep.add("FAIL", "archive", where,
                f"archive with {len(infos)} entries: its contents are not scanned, ship the files instead")
        return
    total = 0
    for info in infos[:5000]:
        if not info.filename.endswith((".xml", ".rels")):
            continue
        try:
            with zf.open(info) as fh:
                raw = fh.read(PART_CAP + 1)
        except Exception:
            rep.add("WARN", "document-metadata", where,
                    f"could not read part {clean(info.filename, 40)}: check the document by hand")
            continue
        if len(raw) > PART_CAP:
            rep.add("WARN", "document-metadata", where, f"part {clean(info.filename, 40)} only partly scanned")
            raw = raw[:PART_CAP]
        total += len(raw)
        if total > DOC_TOTAL_CAP:
            rep.add("WARN", "document-metadata", where, "document only partly scanned (size cap)")
            break
        xml = raw.decode("utf-8", "replace")
        part = f"{where} > {clean(info.filename, 60)}"
        if info.filename in ("docProps/core.xml", "docProps/app.xml", "meta.xml"):
            for tag in ("dc:creator", "cp:lastModifiedBy", "Company", "Manager", "meta:initial-creator"):
                m = re.search(rf"<{tag}>([^<]{{1,200}})</{tag}>", xml)
                if m:
                    rep.add("WARN", "document-metadata", where, f"{tag}: {clean(m.group(1), 50)!r}")
        scan_text(xml, part, rep, cfg, leak_only=True)
        scan_text(re.sub(r"<[^<>]{0,4000}>", "", xml), part, rep, cfg, origin="text", full=False)


def scan_webp(data, where, rep, cfg):
    i = 12
    while i + 8 <= len(data):
        ctype = data[i:i + 4]
        size = struct.unpack("<I", data[i + 4:i + 8])[0]
        payload = data[i + 8:i + 8 + size]
        if ctype == b"EXIF":
            report_tiff(parse_tiff(payload[6:] if payload.startswith(b"Exif\0\0") else payload),
                        where, rep, cfg)
        elif ctype == b"XMP ":
            _xmp(payload, where, rep, cfg)
        i += 8 + size + (size & 1)


def is_archive(data: bytes) -> bool:
    return (data[:2] == b"\x1f\x8b" or data[:3] == b"BZh" or data[:6] == b"\xfd7zXZ\x00"
            or data[:6] == b"7z\xbc\xaf\x27\x1c" or data[:4] == b"Rar!" or data[257:262] == b"ustar")


def scan_media(name: str, data: bytes, where: str, rep: Report, cfg) -> bool:
    """Returns True when the magic bytes match a media, document or archive format."""
    low = name.lower()
    if data[:2] == b"\xff\xd8":
        scan_jpeg(data, where, rep, cfg)
    elif data[:8] == PNG_SIG:
        scan_png(data, where, rep, cfg)
    elif data[:5] == b"%PDF-":
        scan_pdf(data, where, rep, cfg)
    elif data[4:8] == b"ftyp":
        if data[8:12] in (b"heic", b"heix", b"mif1", b"msf1", b"heim", b"heis", b"avif"):
            rep.add("WARN", "photo-metadata", where,
                    "HEIC/AVIF image: cannot be inspected here, convert to JPEG or PNG and strip it")
        else:
            scan_video(data, where, rep, cfg)
    elif data[:6] in (b"GIF87a", b"GIF89a"):
        if b"\x21\xfe" in data:
            rep.add("WARN", "photo-metadata", where, "GIF may carry a comment block")
    elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        scan_webp(data, where, rep, cfg)
    elif data[:4] in (b"II*\0", b"MM\0*"):
        report_tiff(parse_tiff(data), where, rep, cfg)
    elif data[:4] == b"PK\x03\x04":
        scan_zip(data, where, rep, cfg, low)
    elif is_archive(data):
        rep.add("FAIL", "archive", where, "compressed archive: its contents are not scanned, ship the files instead")
    else:
        return False
    return True


# ------------------------------------------------------------ file checks

SENSITIVE_FAIL = [
    ".env", ".env.*", "*.env", ".envrc", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "id_dsa*",
    "id_ecdsa*", "id_ed25519*", "*.keystore", "*.jks", "credentials.json", "client_secret*.json",
    "service-account*.json", "secrets.json", "secrets.yaml", "secrets.yml", "secrets.toml",
    ".npmrc", ".pypirc", ".netrc", ".git-credentials", "*.kdbx", "token.json", "*.ovpn",
    "*.mobileprovision", "settings.local.json",
]
SENSITIVE_OK = [".env.example", ".env.sample", ".env.template", ".env.dist"]
JUNK_WARN = [
    ".ds_store", "thumbs.db", "*.pyc", "*.pyo", "*.log", "*.sqlite", "*.sqlite3", "*.db",
    "*.jsonl", "*.swp", "*.bak", "*.orig", "*.tmp", "*.heic", "arduino_secrets.h",
]
JUNK_DIRS = {"__pycache__", "node_modules", ".venv", "venv", ".idea", ".vscode", ".pytest_cache",
             ".mypy_cache", ".claude", ".ipynb_checkpoints", "dist", "build"}
AGENT_CONFIG = re.compile(r"(?:^|/)(?:\.claude/settings(?:\.local)?\.json|hooks/hooks\.json|\.mcp\.json)$",
                          re.I)
BAD_NAME_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def check_name(rel: str, rep: Report, where: str, cfg=None):
    base = rel.rsplit("/", 1)[-1]
    low = base.lower()
    parts = rel.split("/")[:-1]
    shown = clean(where, 200)
    if BAD_NAME_CHARS.search(rel) or any(sev != "BOM" for _p, _c, sev in hidden_chars(rel)):
        rep.add("FAIL", "bad-filename", shown, "file name with control or invisible characters: rename it")
    rx = cfg.get("_terms_re") if cfg else None
    if rx:
        m = rx.search(rel)
        if m:
            rep.add("FAIL", "private-term", shown, f"private term {clean(m.group(0), 40)!r} in the file name")
    if AGENT_CONFIG.search(rel):
        rep.add("FAIL", "agent-config", shown,
                "Claude Code settings, hooks or MCP config: they grant permissions or run "
                "commands on every user's machine; a skill does not ship them")
    elif low not in SENSITIVE_OK and any(fnmatch.fnmatchcase(low, p) for p in SENSITIVE_FAIL):
        rep.add("FAIL", "sensitive-file", shown, f"file type that usually holds secrets: {clean(base, 60)}")
    elif any(fnmatch.fnmatchcase(low, p) for p in JUNK_WARN):
        rep.add("WARN", "junk-file", shown, f"should not be published: {clean(base, 60)}")
    if low.startswith(".gitleaks"):
        rep.add("WARN", "gitleaks-config", shown,
                "gitleaks configuration in the repo: this scan ignores it, but it silences gitleaks elsewhere")
    bad_dirs = [p for p in parts if p in JUNK_DIRS]
    if bad_dirs:
        rep.add("WARN", "junk-dir", shown, f"inside {clean(bad_dirs[0], 30)}/: add it to .gitignore")


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def decode_text(data: bytes):
    """(text, encoding) for UTF-8, UTF-16 and UTF-32 text with or without a BOM; (None, "") for binary."""
    for bom, enc in ((codecs.BOM_UTF32_LE, "utf-32-le"), (codecs.BOM_UTF32_BE, "utf-32-be"),
                     (codecs.BOM_UTF16_LE, "utf-16-le"), (codecs.BOM_UTF16_BE, "utf-16-be")):
        if data.startswith(bom):
            return data[len(bom):].decode(enc, "replace"), enc
    sample = data[:8192]
    nul = sample.count(0)
    if nul == 0:
        text = data.decode("utf-8", "replace")
        return (text, "utf-8") if looks_text(text[:8192]) else (None, "")
    half = max(1, len(sample) // 2)
    even, odd = sample[0::2].count(0), sample[1::2].count(0)
    if odd > 0.3 * half and even < 0.05 * half:
        return data.decode("utf-16-le", "replace"), "utf-16-le"
    if even > 0.3 * half and odd < 0.05 * half:
        return data.decode("utf-16-be", "replace"), "utf-16-be"
    if nul <= max(2, len(sample) // 100):
        text = data.decode("utf-8", "replace").replace("\0", "")
        if looks_text(text[:8192]):
            return text, "utf-8 with NUL bytes"
    return None, ""


def looks_text(sample: str) -> bool:
    """False when more than 2% of the sample is undecodable bytes or control characters."""
    if not sample:
        return True
    bad = sample.count("\ufffd") + sum(1 for ch in sample if ord(ch) < 32 and ch not in "\t\n\r\f")
    return bad <= len(sample) * 0.02


def is_binary(data: bytes) -> bool:
    return decode_text(data[:8192])[0] is None


TEXT_EXT = CODE_EXT | {".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
                       ".csv", ".tsv", ".xml", ".svg", ".css", ".rst", ".env", ".envrc", ".properties",
                       ".jsonl", ".ipynb", ""}


def scan_bytes(rel: str, data: bytes, rep: Report, cfg, origin: str = "", full: bool = True):
    where = f"{rel} ({origin})" if origin else rel
    ext = os.path.splitext(rel.lower())[1]
    recognised = scan_media(rel, data[:MAX_MEDIA], where, rep, cfg)
    text, enc = decode_text(data[:MAX_TEXT])
    if text is None and not recognised and ext in TEXT_EXT:
        # A text file full of control characters is still read as text.
        text, enc = data[:MAX_TEXT].decode("utf-8", "replace").replace("\0", ""), "utf-8 with control characters"
    if text is None:
        if not recognised and full:
            rep.add("WARN", "binary-file", where,
                    "binary file of unknown type: only searched for secrets and private terms, check it by hand")
        scan_text(data[:MAX_TEXT].decode("latin-1"), rel, rep, cfg, origin=origin, leak_only=True,
                  binary=True)
        return
    if enc != "utf-8" and full:
        rep.add("WARN", "encoding", where, f"{enc} text: scanned here, but other tools may miss it")
    if len(data) > MAX_TEXT:
        rep.add("WARN", "large-text", where, f"only the first {MAX_TEXT} bytes were scanned")
    scan_text(text, rel, rep, cfg, ext=ext, origin=origin, full=full)
    if ext == ".svg" and full:
        if re.search(r"<metadata\b", text):
            rep.add("WARN", "svg-metadata", where, "SVG <metadata> block: check or remove it")
        if re.search(r"sodipodi:docname|inkscape:export-filename", text):
            rep.add("WARN", "svg-metadata", where, "Inkscape file or export names: remove them")
        if re.search(r"<script\b|\son[a-z]{1,30}\s*=", text, re.I):
            rep.add("WARN", "svg-active", where, "SVG with script or event handlers")


def read_regular(path: Path, limit: int = MAX_TEXT):
    """Bytes of a regular file, never through a symlink, never blocking on a FIFO; None otherwise."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks, left = [], limit
        while left > 0:
            chunk = os.read(fd, min(left, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            left -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def read_text_regular(path: Path, limit: int = MAX_TEXT):
    data = read_regular(path, limit)
    return None if data is None else data.decode("utf-8", "replace")


# ------------------------------------------------------------------- git

SAFE_GIT_KEY = re.compile(
    r"core\.(?:repositoryformatversion|filemode|bare|logallrefupdates|ignorecase|precomposeunicode"
    r"|symlinks|autocrlf|safecrlf|eol|quotepath)"
    r"|remote\.[^\n]{1,200}\.(?:url|fetch|pushurl|tagopt|prune)"
    r"|branch\.[^\n]{1,200}\.(?:remote|merge|rebase|pushremote)"
    r"|branch\.[^\n]{1,200}\.vscode-merge-base"
    r"|user\.(?:name|email)|init\.defaultbranch|http\.postbuffer|pull\.rebase|push\.default"
    r"|extensions\.objectformat|lfs\.repositoryformatversion|rerere\.enabled|merge\.conflictstyle"
    r"|color\.ui|fetch\.prune", re.I)


def git_env():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", GIT_CONFIG_NOSYSTEM="1")
    return env


def git(root: Path, *args, input_bytes=None, timeout=180) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-c", "core.quotepath=off", "-c", "log.showSignature=false",
         "-C", str(root), *args],
        input=input_bytes, capture_output=True, timeout=timeout, env=git_env())


def git_config_problem(root: Path):
    """Why git must not run in this folder, or None. Only plain, known config keys are accepted."""
    gd = root / ".git"
    try:
        st = os.lstat(gd)
    except OSError:
        return None
    if not stat.S_ISDIR(st.st_mode):
        return ".git is a file or a link (worktree, submodule or pointer)"
    for extra in ("config.worktree", "commondir"):
        if os.path.lexists(gd / extra):
            return f".git/{extra} is present"
    cfgf = gd / "config"
    if not os.path.lexists(cfgf):
        return None
    if not stat.S_ISREG(os.lstat(cfgf).st_mode):
        return ".git/config is not a regular file"
    res = subprocess.run(["git", "config", "--file", str(cfgf), "--no-includes", "--list", "--null"],
                         capture_output=True, timeout=30, cwd=tempfile.gettempdir(), env=git_env())
    if res.returncode != 0:
        return ".git/config cannot be read"
    for entry in res.stdout.split(b"\0"):
        if entry:
            key = entry.split(b"\n", 1)[0].decode("utf-8", "replace")
            if not SAFE_GIT_KEY.fullmatch(key):
                return f"it sets {clean(key, 60)}"
    return None


def git_root(root: Path):
    if not (root / ".git").exists() or not shutil.which("git"):
        return None
    r = git(root, "rev-parse", "--show-toplevel")
    if r.returncode != 0:
        return None
    return Path(r.stdout.decode().strip()).resolve()


def cat_file_batch(root: Path, shas, timeout=600):
    """Yields (sha, type, content) for each object, read with one `git cat-file --batch`."""
    if not shas:
        return
    out = git(root, "cat-file", "--batch", input_bytes=("\n".join(shas) + "\n").encode(),
              timeout=timeout).stdout
    i = 0
    while i < len(out):
        nl = out.find(b"\n", i)
        if nl == -1:
            return
        header = out[i:nl].split()
        if len(header) != 3:
            i = nl + 1
            continue
        sha, typ, size = header[0].decode(), header[1].decode(), int(header[2])
        yield sha, typ, out[nl + 1:nl + 1 + size]
        i = nl + 1 + size + 1


def list_files(root: Path, use_git: bool, rep: Report):
    """(relative path, untracked) for every file that a publish would include."""
    if use_git:
        out = []
        tracked = git(root, "ls-files", "-z", "--cached").stdout.decode("utf-8", "replace")
        others = git(root, "ls-files", "-z", "--others", "--exclude-standard").stdout.decode(
            "utf-8", "replace")
        ignored = git(root, "ls-files", "-z", "--others", "--ignored", "--exclude-standard",
                      "--directory").stdout.decode("utf-8", "replace")
        seen = set()
        for rel in tracked.split("\0"):
            if rel and rel not in seen:
                seen.add(rel)
                out.append((rel, False))
        for rel in others.split("\0"):
            if rel and rel not in seen:
                seen.add(rel)
                out.append((rel, True))
        n_ign = len([x for x in ignored.split("\0") if x])
        if n_ign:
            rep.add("INFO", "ignored", ".", f"{n_ign} ignored paths are not scanned and not published")
        return out
    out = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for d in list(dirnames):
            if os.path.islink(os.path.join(dirpath, d)):
                out.append((os.path.relpath(os.path.join(dirpath, d), root).replace(os.sep, "/"), False))
        for f in filenames:
            out.append((os.path.relpath(os.path.join(dirpath, f), root).replace(os.sep, "/"), False))
    return out


def scan_tree(root: Path, use_git: bool, rep: Report, cfg) -> set:
    shas = set()
    for rel, untracked in list_files(root, use_git, rep):
        full = root / rel
        where = rel + (" (untracked)" if untracked else "")
        try:
            st = os.lstat(full)
        except OSError:
            continue
        check_name(rel, rep, where, cfg)
        if stat.S_ISLNK(st.st_mode):
            target = os.readlink(full)
            resolved = (full.parent / target).resolve()
            try:
                resolved.relative_to(root.resolve())
                rep.add("WARN", "symlink", clean(where, 200), f"symlink to {clean(target, 60)} (inside the repo)")
            except ValueError:
                rep.add("FAIL", "symlink", clean(where, 200),
                        f"symlink points outside the repo: {clean(target, 60)}")
            continue
        if not stat.S_ISREG(st.st_mode):
            rep.add("WARN", "special-file", clean(where, 200), "not a regular file (FIFO, socket or device)")
            continue
        if st.st_size > FAIL_SIZE:
            rep.add("FAIL", "large-file", where, f"{st.st_size // 1_000_000} MB: too big for a skill repo")
        elif st.st_size > WARN_SIZE:
            rep.add("WARN", "large-file", where, f"{st.st_size // 1_000_000} MB: is it needed?")
        data = read_regular(full, MAX_MEDIA)
        if data is None:
            continue
        if st.st_size <= MAX_MEDIA:
            shas.add(git_blob_sha(data))
        try:
            scan_bytes(rel, data, rep, cfg, origin="untracked" if untracked else "")
        except Exception as exc:  # fail closed: an unscannable file is a finding
            rep.add("FAIL", "scanner-error", where, f"could not scan this file ({type(exc).__name__}): check it by hand")
    return shas


def scan_history(root: Path, rep: Report, cfg, current_shas: set):
    r = git(root, "rev-list", "--all", "--objects")
    if r.returncode != 0:
        return
    paths = {}
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        sha, _, path = line.partition(" ")
        if path:
            paths.setdefault(sha, path)
    if not paths:
        return
    check = git(root, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)",
                input_bytes=("\n".join(paths) + "\n").encode())
    wanted, total, skipped = [], 0, 0
    for line in check.stdout.decode().splitlines():
        parts = line.split()
        if len(parts) != 3 or parts[1] != "blob":
            continue
        sha, size = parts[0], int(parts[2])
        if sha in current_shas:
            continue
        rel = paths[sha]
        check_name(rel, rep, f"{rel} (history {sha[:7]})", cfg)
        if size > MAX_MEDIA or total + size > MAX_HISTORY_TOTAL:
            skipped += 1
            continue
        total += size
        wanted.append(sha)
    if skipped:
        rep.add("WARN", "history-partial", ".", f"{skipped} large blobs in the history were not scanned")
    hist = Report()
    hist.CAP = 10 ** 9
    for sha, typ, data in cat_file_batch(root, wanted):
        rel = paths.get(sha, sha)
        origin = f"history {sha[:7]}, find it with git log --all --find-object={sha[:12]}"
        try:
            scan_bytes(rel, data, hist, cfg, full=False, origin=origin)
        except Exception as exc:
            hist.add("FAIL", "scanner-error", f"{rel} ({origin})", f"could not scan ({type(exc).__name__})")
    # The same leak repeated in every old version of a file is reported once
    # (different secrets differ in their masked fingerprint).
    seen = set()
    for f in hist.findings:
        key = (f.severity, f.check, f.path.split(" (", 1)[0], f.message)
        if key not in seen:
            seen.add(key)
            rep.add(f.severity, f.check, f.path, f.message, f.line)


IDENT = re.compile(rb"^(.*) <(.*)> -?\d+ [+-]\d{4}$")


def parse_commit(raw: bytes):
    """(author, committer, message) from a raw commit object; identities are None if unreadable."""
    head, _sep, msg = raw.partition(b"\n\n")
    author = committer = None
    for line in head.split(b"\n"):
        if line.startswith(b" "):
            continue
        for prefix in (b"author ", b"committer "):
            if line.startswith(prefix):
                m = IDENT.match(line[len(prefix):])
                ident = None
                if m:
                    ident = f"{m.group(1).decode('utf-8', 'replace')} <{m.group(2).decode('utf-8', 'replace')}>"
                if prefix == b"author ":
                    author = ident
                else:
                    committer = ident
    return author, committer, msg.decode("utf-8", "replace")


def scan_commits(root: Path, rep: Report, cfg):
    r = git(root, "rev-list", "--all")
    if r.returncode != 0:
        return
    shas = r.stdout.decode().split()
    identities: dict = {}
    trailers = set()
    for sha, typ, raw in cat_file_batch(root, shas):
        if typ != "commit":
            continue
        author, committer, body = parse_commit(raw)
        if author is None or committer is None:
            rep.add("FAIL", "commit-identity", "git", f"commit {sha[:7]}: author or committer cannot be read")
        for ident in (author, committer):
            if ident:
                identities[ident] = identities.get(ident, 0) + 1
        for t in re.findall(r"(?im)^co-authored-by:[ \t]*(.+)$", body):
            trailers.add(t.strip())
        scan_text(body, f"commit {sha[:7]}", rep, cfg, origin="message", full=False)
    allowed = set(cfg["author_identities"])
    rx = cfg.get("_terms_re")
    for ident, n in sorted(identities.items()):
        if rx and ident not in allowed and rx.search(ident):
            rep.add("FAIL", "private-term", "git", f"a commit identity contains a private term ({n})")
        if BAD_NAME_CHARS.search(ident) or any(sev != "BOM" for _p, _c, sev in hidden_chars(ident)):
            rep.add("FAIL", "commit-identity", "git", "commit identity with control or invisible characters")
        if PLATFORM_IDENTITY.match(ident):
            rep.add("INFO", "commit-identity", "git", f"platform identity (merges, bots): {clean(ident, 70)} ({n})")
        elif allowed and ident not in allowed:
            rep.add("FAIL", "commit-identity", "git", f"identity not in author_identities: {clean(ident, 70)} ({n})")
        else:
            rep.add("INFO", "commit-identity", "git", f"public on GitHub: {clean(ident, 70)} ({n})")
    for t in sorted(trailers):
        rep.add("INFO", "co-author", "git", f"Co-authored-by: {clean(t, 70)}")
    rem = git(root, "remote", "-v")
    for line in rem.stdout.decode("utf-8", "replace").splitlines():
        m = URL_CREDENTIALS.search(line)
        if m and not is_placeholder(m.group(2)):
            rep.add("FAIL", "remote-credentials", "git", f"remote URL carries a credential {mask(m.group(2))}")


# ---------------------------------------------------------------- gitleaks

GITLEAKS_DEFAULT_CONFIG = "[extend]\nuseDefault = true\n"


def run_gitleaks(root: Path, use_git: bool, rep: Report, files):
    """gitleaks with its default rules only, on a copy of exactly the files a publish
    would include, plus the history. Repo-level gitleaks config and allow comments
    are ignored, so the scanned repo cannot silence it."""
    exe = shutil.which("gitleaks")
    if not exe:
        rep.add("FAIL", "gitleaks", ".", "gitleaks is not installed: install it, or pass --no-gitleaks "
                "and say in the release report that it was skipped")
        return
    with tempfile.TemporaryDirectory() as td:
        copy = Path(td) / "tree"
        copy.mkdir()
        for rel, _u in files:
            if rel.rsplit("/", 1)[-1].lower().startswith(".gitleaks"):
                continue
            data = read_regular(root / rel, MAX_MEDIA)
            if data is None:
                continue
            dest = copy / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        conf = Path(td) / "gitleaks.toml"
        conf.write_text(GITLEAKS_DEFAULT_CONFIG, encoding="utf-8")
        ignore_dir = Path(td) / "no-ignore"
        ignore_dir.mkdir()
        modes = [("dir", ["dir", str(copy)], ["detect", "--no-git", "--source", str(copy)])]
        if use_git:
            modes.append(("git", ["git", str(root)], ["detect", "--source", str(root)]))
        for label, new, legacy in modes:
            report = os.path.join(td, f"{label}.json")
            common = ["--no-banner", "--redact", "--report-format", "json", "--report-path", report,
                      "--exit-code", "0", "--config", str(conf), "--gitleaks-ignore-path", str(ignore_dir),
                      "--ignore-gitleaks-allow"]
            res = subprocess.run([exe, *new, *common], capture_output=True, timeout=900,
                                 env=git_env(), cwd=td)
            if res.returncode != 0 and b"unknown command" in res.stderr.lower():
                res = subprocess.run([exe, *legacy, *common], capture_output=True, timeout=900,
                                     env=git_env(), cwd=td)
            if res.returncode != 0:
                rep.add("FAIL", "gitleaks", ".", f"gitleaks {label} failed: {clean(res.stderr[-200:], 120)}")
                continue
            try:
                with open(report, encoding="utf-8") as fh:
                    results = json.load(fh) or []
            except (OSError, ValueError):
                results = []
            base = copy if label == "dir" else root
            for f in results:
                file = str(f.get("File", ""))
                try:
                    file = os.path.relpath(file, base) if os.path.isabs(file) else file
                except ValueError:
                    pass
                commit = f" commit {clean(f.get('Commit'), 7)}" if f.get("Commit") else ""
                rep.add("FAIL", f"gitleaks-{label}", clean(file.replace(os.sep, "/"), 200),
                        f"{clean(f.get('RuleID', 'secret'), 40)}{commit}", int(f.get("StartLine") or 0))


# --------------------------------------------------------- skill and repo

FRONTMATTER = re.compile(r"\A---[ \t]*\n(.*?)\n---[ \t]*(?:\n|\Z)", re.S)
LINK = re.compile(r"\[[^\]\n]{0,300}\]\(([^)\s]{1,500})(?:[ \t]+\"[^\"\n]{0,300}\")?\)")


def parse_frontmatter(text: str):
    m = FRONTMATTER.match(text)
    if not m:
        return None, text
    fields, key, block = {}, None, []
    for line in m.group(1).splitlines():
        km = re.match(r"^([A-Za-z0-9_-]{1,64}):[ \t]*(.*)$", line)
        if km and not line.startswith((" ", "\t")):
            if key and block:
                fields[key] = " ".join(s.strip() for s in block).strip()
            key, val, block = km.group(1), km.group(2).strip(), []
            if val in (">", "|", ">-", "|-", ">+", "|+"):
                fields[key] = ""
            else:
                fields[key] = val.strip("\"'") if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'" else val
                if val:
                    key = None
        elif key:
            block.append(line)
    if key and block:
        fields[key] = " ".join(s.strip() for s in block).strip()
    return fields, text[m.end():]


def check_skill(root: Path, rep: Report, cfg):
    text = read_text_regular(root / "SKILL.md")
    if text is None:
        rep.add("FAIL", "skill-md", "SKILL.md", "missing (or not a regular file): this is not a skill folder")
        return
    fields, body = parse_frontmatter(text)
    if fields is None:
        rep.add("FAIL", "skill-md", "SKILL.md", "no YAML frontmatter (--- name / description ---)")
        return
    name, desc = fields.get("name", ""), fields.get("description", "")
    for key in fields:
        if key == "hooks":
            rep.add("FAIL", "skill-frontmatter", "SKILL.md",
                    "frontmatter 'hooks' runs commands for every user who installs the skill")
        elif key == "allowed-tools":
            rep.add("WARN", "skill-frontmatter", "SKILL.md",
                    f"frontmatter 'allowed-tools' pre-approves tools for every user: {clean(fields[key], 60)!r}")
        elif key not in ("name", "description", "license"):
            rep.add("WARN", "skill-frontmatter", "SKILL.md", f"frontmatter key {clean(key, 30)!r}: read what it does")
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name or "") or len(name) > 64:
        rep.add("FAIL", "skill-md", "SKILL.md", f"name must be lowercase-with-hyphens, max 64: {clean(name, 40)!r}")
    elif re.search(r"anthropic|claude", name):
        rep.add("WARN", "skill-md", "SKILL.md", "name contains a reserved word (anthropic, claude)")
    if not desc:
        rep.add("FAIL", "skill-md", "SKILL.md", "description is empty")
    elif len(desc) > 1024:
        rep.add("FAIL", "skill-md", "SKILL.md", f"description is {len(desc)} characters, the limit is 1024")
    if re.search(r"<[A-Za-z/!]", desc):
        rep.add("WARN", "skill-md", "SKILL.md", "description contains angle-bracket tags")
    n_lines = body.count("\n") + 1
    if n_lines > 500:
        rep.add("WARN", "skill-md", "SKILL.md", f"body is {n_lines} lines: move detail into references/")
    if cfg.get("require_intake"):
        heads = re.findall(r"(?m)^#{2,3}[ \t]+(.+)$", body)
        first = " ".join(heads[:4]).lower()
        if not re.search(r"intake|question|interview|domande|ask", first):
            rep.add("WARN", "skill-intake", "SKILL.md", "no intake step among the first headings: the skill should start by asking")


def check_links(root: Path, rep: Report, files):
    for rel, _u in files:
        # templates/ holds files meant for other repos: their links point there.
        if not rel.endswith(".md") or rel.startswith("templates/"):
            continue
        full = root / rel
        text = read_text_regular(full)
        if text is None:
            continue
        for m in LINK.finditer(text):
            target = m.group(1)
            if re.match(r"^(?:[a-z][a-z0-9+.-]*:|#|//)", target, re.I):
                continue
            target = target.split("#", 1)[0].split("?", 1)[0]
            if not target:
                continue
            dest = (full.parent / target).resolve()
            try:
                dest.relative_to(root.resolve())
            except ValueError:
                rep.add("WARN", "link", clean(rel, 200), f"link leaves the repo: {clean(target, 60)}", line_of(text, m.start()))
                continue
            if not dest.exists():
                rep.add("WARN", "link", clean(rel, 200), f"broken relative link: {clean(target, 60)}", line_of(text, m.start()))


def check_repo_files(root: Path, rep: Report, cfg, files):
    names = {rel for rel, _ in files}
    for doc in sorted(n for n in names if "/" not in n and re.match(
            r"^(?:README|SECURITY|SKILL|LICEN[CS]E|CONTRIBUTING)(?:\.md|\.txt)?$", n)):
        text = read_text_regular(root / doc)
        if text is None:
            continue
        for m in PLACEHOLDER_LEFT.finditer(text):
            rep.add("FAIL", "placeholder", doc, f"template placeholder left: {m.group(0)}",
                    line_of(text, m.start()))
    lic = next((n for n in ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE") if n in names), None)
    lic_text = read_text_regular(root / lic) if lic else None
    if lic_text is None:
        rep.add("FAIL", "license", ".", "no LICENSE file (or it is not a regular file)")
    else:
        if "Permission is hereby granted, free of charge" not in lic_text and "MIT License" not in lic_text:
            rep.add("INFO", "license", lic, "not the MIT text: make sure the licence is the one agreed")
        holder = cfg.get("copyright_holder")
        if holder and holder not in lic_text:
            rep.add("WARN", "license", lic, f"copyright holder {holder!r} not found")
    readme = read_text_regular(root / "README.md") if "README.md" in names else None
    if readme is None:
        rep.add("FAIL", "readme", ".", "no README.md (or it is not a regular file)")
    else:
        heads = " ".join(re.findall(r"(?m)^#{1,3}[ \t]+(.+)$", readme)).lower()
        for want, rx in (("Install", r"install"), ("Usage", r"usage|how to use|use it"),
                         ("Security", r"security"), ("Licence", r"licen[cs]e")):
            if not re.search(rx, heads):
                rep.add("WARN", "readme", "README.md", f"no {want} section")
    sec = read_text_regular(root / "SECURITY.md") if "SECURITY.md" in names else None
    if sec is None:
        rep.add("WARN", "security-md", ".", "no SECURITY.md (threat model and how to report)")
    elif "report a vulnerability" not in sec.lower() and "private vulnerability reporting" not in sec.lower():
        rep.add("WARN", "security-md", "SECURITY.md", "does not say how to report privately")
    if ".gitignore" not in names:
        rep.add("WARN", "gitignore", ".", "no .gitignore")
    if ".gitmodules" in names:
        rep.add("WARN", "submodules", ".gitmodules", "submodules pull in code that this scan does not see")
    workflows = [n for n in names if re.match(r"^\.github/workflows/[^/]+\.ya?ml$", n)]
    if not workflows:
        rep.add("WARN", "ci", ".", "no CI workflow in .github/workflows")
    for wf in sorted(workflows):
        check_workflow(root, wf, rep)
    for req in sorted(n for n in names if re.match(r"^(?:.*/)?requirements[^/]*\.txt$", n)):
        text = read_text_regular(root / req)
        if text is None:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            s = line.split("#", 1)[0].strip()
            if s and not s.startswith("-") and "==" not in s and " @ " not in s:
                rep.add("WARN", "unpinned-dependency", clean(req, 200), f"not pinned with ==: {clean(s, 50)}", i)
    for pkg in sorted(n for n in names if n.endswith("package.json") and "node_modules/" not in n):
        folder = pkg[: -len("package.json")]
        if not any(folder + lock in names for lock in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")):
            rep.add("WARN", "unpinned-dependency", clean(pkg, 200), "no lockfile next to package.json")


USES = re.compile(r"(?m)^[ \t]*-?[ \t]*uses:[ \t]*['\"]?([^\s'\"#]{1,300})")


def check_workflow(root: Path, wf: str, rep: Report):
    text = read_text_regular(root / wf, 1_000_000)
    if text is None:
        rep.add("WARN", "ci", clean(wf, 200), "workflow is not a regular file")
        return
    wf = clean(wf, 200)
    n_checkout = 0
    for m in USES.finditer(text):
        ref = m.group(1)
        if ref.startswith(("./", "docker://")):
            continue
        if "actions/checkout@" in ref:
            n_checkout += 1
        if not re.search(r"@[0-9a-f]{40}$", ref):
            rep.add("FAIL", "ci-unpinned", wf, f"action not pinned to a commit SHA: {clean(ref, 60)}",
                    line_of(text, m.start()))
    if re.search(r"\bpull_request_target\b", text):
        rep.add("FAIL", "ci-trigger", wf, "pull_request_target runs fork code with secrets")
    if not re.search(r"(?m)^permissions[ \t]*:", text):
        rep.add("WARN", "ci-permissions", wf, "no top-level permissions (use contents: read)")
    if re.search(r"permissions[ \t]*:[ \t]*write-all", text):
        rep.add("FAIL", "ci-permissions", wf, "permissions: write-all")
    if "${{ secrets." in text.replace("${{secrets.", "${{ secrets."):
        rep.add("WARN", "ci-secrets", wf, "uses repository secrets: a skill CI should not need any")
    if n_checkout and text.count("persist-credentials: false") < n_checkout:
        rep.add("WARN", "ci-credentials", wf, "checkout without persist-credentials: false")


# --------------------------------------------------------------- main scan

def scan(root: Path, cfg, *, history=True, gitleaks=True) -> Report:
    rep = Report()
    root = root.resolve()
    problem = git_config_problem(root) if os.path.lexists(root / ".git") else None
    if problem:
        rep.add("FAIL", "unsafe-git", ".",
                f"git is not run in this folder ({problem}): scan a fresh `git clone --no-local` copy "
                "or stage the files again; history not scanned")
        top = None
    else:
        top = git_root(root)
    use_git = top is not None and top == root
    if top is not None and top != root:
        rep.add("WARN", "git", ".", f"folder is inside another repo ({clean(top, 60)}): history not scanned; stage it in its own folder")
    elif top is None and not problem:
        rep.add("INFO", "git", ".", "not a git repo yet: history checks skipped")
    n_terms = len(cfg["_terms"])
    if cfg.get("_source"):
        rep.add("INFO", "config", ".", f"owner config {clean(cfg['_source'], 120)}, {n_terms} private terms")
    else:
        rep.add("WARN", "config", ".", "no owner config.json: commit identities are not checked")
    if not n_terms:
        rep.add("WARN", "config", ".", "no private terms loaded: names of people, clients and "
                "private projects are not checked (see README, private settings)")
    files = list_files(root, use_git, Report())
    shas: set = set()
    try:
        shas = scan_tree(root, use_git, rep, cfg)
    except Exception as exc:
        rep.add("FAIL", "scanner-error", ".", f"file scan stopped ({type(exc).__name__}): fix and re-run")
    for label, fn in (("SKILL.md", lambda: check_skill(root, rep, cfg)),
                      ("repo files", lambda: check_repo_files(root, rep, cfg, files)),
                      ("links", lambda: check_links(root, rep, files)),
                      ("history", lambda: scan_history(root, rep, cfg, shas) if use_git and history else None),
                      ("commits", lambda: scan_commits(root, rep, cfg) if use_git and history else None),
                      ("gitleaks", lambda: run_gitleaks(root, use_git, rep, files) if gitleaks else None)):
        try:
            fn()
        except Exception as exc:
            rep.add("FAIL", "scanner-error", ".", f"{label} check stopped ({type(exc).__name__}): fix and re-run")
    if not gitleaks:
        rep.add("INFO", "gitleaks", ".", "gitleaks skipped (--no-gitleaks): say so in the release report")
    return rep.finish()


def print_report(rep: Report, root: Path, as_json: bool):
    summary = {s: rep.count(s) for s in SEVERITIES}
    if as_json:
        print(json.dumps({"version": VERSION, "root": str(root), "summary": summary,
                          "findings": [asdict(f) for f in rep.findings]}, indent=2))
        return
    for f in rep.findings:
        path = clean(f.path, 200)
        loc = f"{path}:{f.line}" if f.line else path
        print(f"{f.severity:4}  {clean(f.check, 30):22} {loc}  {clean(f.message, 300)}")
    print(f"\nrelease_scan {VERSION}: FAIL {summary['FAIL']}, WARN {summary['WARN']}, INFO {summary['INFO']}")


# ------------------------------------------------------------------ strip

def atomic_write(path: Path, data: bytes, mode: int):
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".strip-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(tmp, stat.S_IMODE(mode))
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


JPEG_KEEP_APP = {0xE0, 0xE2, 0xEE}  # JFIF, ICC profile, Adobe colour transform


def strip_jpeg(data: bytes):
    """Drops every APPn block except JFIF, ICC and Adobe, every comment, and anything after EOI."""
    drops, removed, eoi = [], [], None
    for marker, start, end, _payload in jpeg_walk(data):
        if marker == 0xD9:
            eoi = end
            break
        if (0xE0 <= marker <= 0xEF and marker not in JPEG_KEEP_APP) or marker == 0xFE:
            drops.append((start, end))
            removed.append("COM" if marker == 0xFE else f"APP{marker - 0xE0}")
    if eoi is None:
        raise ValueError("no end-of-image marker (truncated JPEG): re-export it")
    out, last = [], 0
    for s, e in drops:
        out.append(data[last:s])
        last = e
    out.append(data[last:eoi])
    if eoi < len(data):
        removed.append(f"{len(data) - eoi} bytes after the end of the image")
    new = b"".join(out)
    if b"Exif\0\0" in new or b"<x:xmpmeta" in new or b"ns.adobe.com/xap" in new:
        raise ValueError("metadata is still inside the image data after stripping: re-export the image")
    return new, removed


def strip_png(data: bytes):
    out = [PNG_SIG]
    removed = []
    end = None
    for ctype, start, cend, _payload in png_chunks(data):
        if ctype in PNG_SAFE:
            out.append(data[start:cend])
        else:
            removed.append(clean(ctype, 8))
        if ctype == b"IEND":
            end = cend
    if end is None:
        raise ValueError("no IEND chunk (truncated PNG)")
    if end < len(data):
        removed.append(f"{len(data) - end} bytes after the end of the image")
    return b"".join(out), removed


def strip_file(path: Path, force=False) -> str:
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise ValueError("refusing a symlink")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError("not a regular file")
    if st.st_size > MAX_MEDIA:
        raise ValueError("file too large")
    data = read_regular(path, MAX_MEDIA)
    if data is None:
        raise ValueError("cannot read it as a regular file")
    if data[:2] == b"\xff\xd8":
        orient = jpeg_orientation(data)
        if orient not in (None, 1) and not force:
            raise ValueError(f"EXIF orientation {orient}: rotate the pixels first (or --force), "
                             "stripping would show the photo sideways")
        new, removed = strip_jpeg(data)
    elif data[:8] == PNG_SIG:
        new, removed = strip_png(data)
    else:
        raise ValueError("only JPEG and PNG are supported: re-export other formats without metadata")
    if not removed:
        return "no metadata"
    atomic_write(path, new, st.st_mode)
    return "removed " + ", ".join(sorted(set(removed)))


# ------------------------------------------------------------------- CLI

def main(argv=None):
    ap = argparse.ArgumentParser(prog="release_scan.py", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="scan a staging folder before it goes public")
    sc.add_argument("path")
    sc.add_argument("--no-history", action="store_true", help="skip git history and commits")
    sc.add_argument("--no-gitleaks", action="store_true", help="do not run gitleaks")
    sc.add_argument("--json", action="store_true")
    sc.add_argument("--strict", action="store_true", help="exit 1 on WARN too")
    sc.add_argument("--config", help="owner config file (default $SKILL_RELEASE_HOME/config.json)")
    st = sub.add_parser("strip", help="remove metadata from JPEG / PNG files in place")
    st.add_argument("files", nargs="+")
    st.add_argument("--force", action="store_true", help="strip even if EXIF orientation is lost")
    args = ap.parse_args(argv)

    if args.cmd == "scan":
        root = Path(args.path)
        if not root.is_dir():
            print(f"not a folder: {clean(root, 200)}", file=sys.stderr)
            return 2
        cfg = load_config(args.config)
        rep = scan(root, cfg, history=not args.no_history, gitleaks=not args.no_gitleaks)
        print_report(rep, root.resolve(), args.json)
        if rep.count("FAIL") or (args.strict and rep.count("WARN")):
            return 1
        return 0

    status = 0
    for f in args.files:
        try:
            print(f"{clean(f, 200)}: {strip_file(Path(f), force=args.force)}")
        except (ValueError, OSError) as exc:
            print(f"{clean(f, 200)}: NOT stripped, {clean(exc, 200)}", file=sys.stderr)
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
