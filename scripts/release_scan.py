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
    secret = secret.strip()
    return f"{secret[:4]}...({len(secret)} chars)"


def clean(value, limit=80) -> str:
    """Printable, single-line, truncated version of an untrusted string."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    value = "".join(ch if ch.isprintable() else "?" for ch in str(value))
    return value if len(value) <= limit else value[:limit] + "..."


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


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
HIDDEN_CHARS = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff"
                          "\U000e0000-\U000e007f]")
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
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
SCRIPT_SRC = re.compile(r"<script\b[^>]*\bsrc\s*=\s*[\"']https?://[^\"']+[\"'][^>]*>", re.I)


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
              full: bool = True):
    """Content rules for one text: a file, a history blob or a commit message.

    full=False (history and commit messages) keeps the leak rules and drops the
    style, inventory and code rules, which only matter for the current files.
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
        user, pwd = m.group(1), m.group(2)
        if not is_placeholder(pwd) and pwd.lower() not in PLACEHOLDER_LOGINS \
                and user.lower() not in PLACEHOLDER_LOGINS:
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
    for m in GENERIC_SECRET.finditer(text):
        val = m.group(2)
        if is_placeholder(val) or any(a <= m.start(2) < b for a, b in covered):
            continue
        rep.add("WARN", "secret-assignment", where,
                f"{m.group(1)} assigned a literal {mask(val)}: confirm it is not real",
                line_of(text, m.start()))
    for m in HEX64.finditer(text):
        start = text.rfind("\n", 0, m.start()) + 1
        end = text.find("\n", m.end())
        line = text[start:end if end != -1 else len(text)]
        if CRYPTO_KEY_LINE.search(line):
            rep.add("FAIL", "crypto-private-key", where,
                    f"64-hex value next to a key word {mask(m.group(0))}", line_of(text, m.start()))
    for m in MNEMONIC.finditer(text):
        rep.add("FAIL", "seed-phrase", where, "looks like a wallet seed phrase",
                line_of(text, m.start()))

    if cfg.get("_terms_re"):
        for m in cfg["_terms_re"].finditer(text):
            rep.add("FAIL", "private-term", where, f"private term {clean(m.group(0), 40)!r}",
                    line_of(text, m.start()))

    if MEMORY_MARKER in text:
        rep.add("FAIL", "claude-memory", where, "looks like a Claude memory file")
    if ext == ".jsonl" and TRANSCRIPT_MARKER.search(text):
        rep.add("FAIL", "claude-transcript", where, "looks like a Claude session transcript")

    for m in EMAIL.finditer(text):
        if not email_allowed(m.group(1), m.group(2), m.group(3), cfg):
            rep.add("WARN", "email", where, f"email address {clean(m.group(0), 60)}",
                    line_of(text, m.start()))
    for m in PHONE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 9 <= len(digits) <= 15:
            rep.add("WARN", "phone", where, f"phone number {clean(m.group(0), 30)}",
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

    for m in HIDDEN_CHARS.finditer(text):
        cp = ord(m.group(0))
        if cp == 0xFEFF and m.start() == 0:
            if full:
                rep.add("WARN", "bom", where, "file starts with a byte order mark")
            continue
        rep.add("FAIL", "hidden-unicode", where,
                f"invisible or direction-changing character U+{cp:04X}: can hide text from reviewers",
                line_of(text, m.start()))
    if not full:
        return
    for m in CURL_PIPE_SHELL.finditer(text):
        rep.add("WARN", "curl-pipe-shell", where,
                "download piped into a shell: never run it on the reviewer's machine",
                line_of(text, m.start()))
    if ext == ".md":
        for m in HTML_COMMENT.finditer(text):
            rep.add("INFO", "hidden-comment", where,
                    f"HTML comment, not shown when rendered: {clean(m.group(1).strip(), 60)!r}",
                    line_of(text, m.start()))
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


def jpeg_segments(data: bytes):
    """Yields (marker, start, end, payload) for each segment before the scan data."""
    if data[:2] != b"\xff\xd8":
        return
    i = 2
    n = len(data)
    while i < n:
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
            return
        if i + 2 > n:
            return
        seglen = struct.unpack(">H", data[i:i + 2])[0]
        if seglen < 2 or i + seglen > n:
            return
        yield marker, start, i + seglen, data[i + 2:i + seglen]
        if marker == 0xDA:
            return
        i += seglen


def jpeg_orientation(data: bytes):
    for marker, _s, _e, payload in jpeg_segments(data):
        if marker == 0xE1 and payload.startswith(b"Exif\0\0"):
            return parse_tiff(payload[6:]).get("ifd0", {}).get(0x0112)
    return None


def scan_jpeg(data, where, rep, cfg):
    for marker, _s, _e, payload in jpeg_segments(data):
        if marker == 0xE1 and payload.startswith(b"Exif\0\0"):
            report_tiff(parse_tiff(payload[6:]), where, rep, cfg)
        elif marker == 0xE1 and b"ns.adobe.com/xap" in payload[:64]:
            _xmp(payload, where, rep, cfg)
        elif marker == 0xED:
            if b"8BIM\x04\x04" in payload:
                rep.add("WARN", "photo-metadata", where,
                        "IPTC block (APP13): can hold author, caption and place fields")
                _terms_in_strings([payload.decode("latin-1")], where, rep, cfg)
            else:
                rep.add("INFO", "photo-metadata", where, "Photoshop block (APP13) with no IPTC data")
        elif marker == 0xFE:
            rep.add("WARN", "photo-metadata", where, f"JPEG comment: {clean(payload, 50)!r}")
            _terms_in_strings([payload.decode("latin-1")], where, rep, cfg)


def _xmp(payload: bytes, where, rep, cfg):
    text = payload.decode("utf-8", "replace")
    if re.search(r"GPS(?:Latitude|Longitude)", text):
        rep.add("FAIL", "gps-location", where, "XMP GPS location: strip it before publishing")
    names = re.findall(r"<(?:dc:creator|xmp:CreatorTool|photoshop:AuthorsPosition|exif:\w+)", text)
    rep.add("WARN", "photo-metadata", where,
            "XMP metadata block" + (f" ({', '.join(sorted(set(n[1:] for n in names)))[:80]})" if names else ""))
    _terms_in_strings([text], where, rep, cfg)


PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_META = {b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME"}


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
    for ctype, _s, _e, payload in png_chunks(data):
        if ctype == b"tEXt":
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


def _png_text(key: bytes, val: bytes, where, rep, cfg):
    k = clean(key, 30)
    text = val.decode("utf-8", "replace")
    if k == "XML:com.adobe.xmp" or "ns.adobe.com/xap" in text[:200]:
        _xmp(val, where, rep, cfg)
        return
    rep.add("WARN", "photo-metadata", where, f"PNG text {k}: {clean(text, 50)!r}")
    _terms_in_strings([text], where, rep, cfg)


def scan_pdf(data, where, rep, cfg):
    text = data.decode("latin-1")
    for m in re.finditer(r"/(Author|Creator|Producer|Title|Subject|Keywords)\s*\(([^)]{0,200})\)", text):
        sev = "INFO" if m.group(1) == "Producer" else "WARN"
        rep.add(sev, "pdf-metadata", where, f"PDF {m.group(1)}: {clean(m.group(2), 50)!r}")
    if "<x:xmpmeta" in text:
        rep.add("WARN", "pdf-metadata", where, "PDF has an XMP metadata packet")
    _terms_in_strings([text], where, rep, cfg)


def scan_video(data, where, rep, cfg):
    if b"\xa9xyz" in data or b"com.apple.quicktime.location" in data:
        rep.add("FAIL", "gps-location", where, "video has a recording location: strip it (ffmpeg -map_metadata -1)")
    for tag, label in ((b"com.apple.quicktime.make", "device make"), (b"\xa9mak", "device make"),
                       (b"\xa9mod", "device model"), (b"com.apple.quicktime.model", "device model")):
        if tag in data:
            rep.add("WARN", "video-metadata", where, f"video metadata: {label}")


def scan_zip(data, where, rep, cfg, name):
    import io
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except (zipfile.BadZipFile, OSError, ValueError):
        rep.add("WARN", "archive", where, "unreadable archive")
        return
    office = any(i.filename == "docProps/core.xml" for i in infos) or name.endswith(
        (".docx", ".xlsx", ".pptx"))
    if not office:
        rep.add("WARN", "archive", where,
                f"archive with {len(infos)} entries: contents are not scanned, ship the files instead")
        return
    for info in infos:
        if info.filename in ("docProps/core.xml", "docProps/app.xml") and info.file_size <= 1_000_000:
            try:
                xml = zf.read(info).decode("utf-8", "replace")
            except Exception:
                continue
            for tag in ("dc:creator", "cp:lastModifiedBy", "Company", "Manager"):
                m = re.search(rf"<{tag}>([^<]{{1,200}})</{tag}>", xml)
                if m:
                    rep.add("WARN", "document-metadata", where, f"{tag}: {clean(m.group(1), 50)!r}")
            _terms_in_strings([xml], where, rep, cfg)


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


def scan_media(name: str, data: bytes, where: str, rep: Report, cfg) -> bool:
    """Returns True when the bytes were recognised as a media / document format."""
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
    else:
        return False
    return True


# ------------------------------------------------------------ file checks

SENSITIVE_FAIL = [
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "id_dsa*", "id_ecdsa*",
    "id_ed25519*", "*.keystore", "*.jks", "credentials.json", "client_secret*.json",
    "service-account*.json", "secrets.json", "secrets.yaml", "secrets.yml", "secrets.toml",
    ".npmrc", ".pypirc", ".netrc", ".git-credentials", "*.kdbx", "token.json", "*.ovpn",
    "*.mobileprovision", "settings.local.json",
]
SENSITIVE_OK = [".env.example", ".env.sample", ".env.template", ".env.dist"]
JUNK_WARN = [
    ".DS_Store", "Thumbs.db", "*.pyc", "*.pyo", "*.log", "*.sqlite", "*.sqlite3", "*.db",
    "*.jsonl", "*.swp", "*.bak", "*.orig", "*.tmp", "*.heic", "arduino_secrets.h",
]
JUNK_DIRS = {"__pycache__", "node_modules", ".venv", "venv", ".idea", ".vscode", ".pytest_cache",
             ".mypy_cache", ".claude", ".ipynb_checkpoints", "dist", "build"}
MEDIA_EXTS = {".jpg", ".jpeg", ".png", ".pdf", ".mp4", ".mov", ".m4v", ".m4a", ".heic", ".heif",
              ".gif", ".webp", ".tif", ".tiff", ".docx", ".xlsx", ".pptx", ".odt", ".ods",
              ".odp", ".zip", ".avif"}


AGENT_CONFIG = re.compile(r"(?:^|/)(?:\.claude/settings(?:\.local)?\.json|hooks/hooks\.json|\.mcp\.json)$")


def check_name(rel: str, rep: Report, where: str):
    base = rel.rsplit("/", 1)[-1]
    parts = rel.split("/")[:-1]
    if AGENT_CONFIG.search(rel):
        rep.add("FAIL", "agent-config", where,
                "Claude Code settings, hooks or MCP config: they grant permissions or run "
                "commands on every user's machine; a skill does not ship them")
    elif base not in SENSITIVE_OK and any(fnmatch.fnmatch(base, p) for p in SENSITIVE_FAIL):
        rep.add("FAIL", "sensitive-file", where, f"file type that usually holds secrets: {base}")
    elif any(fnmatch.fnmatch(base, p) for p in JUNK_WARN):
        rep.add("WARN", "junk-file", where, f"should not be published: {base}")
    bad_dirs = [p for p in parts if p in JUNK_DIRS]
    if bad_dirs:
        rep.add("WARN", "junk-dir", where, f"inside {bad_dirs[0]}/: add it to .gitignore")


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def is_binary(data: bytes) -> bool:
    return b"\0" in data[:8192]


def scan_bytes(rel: str, data: bytes, rep: Report, cfg, origin: str = "", full: bool = True):
    where = f"{rel} ({origin})" if origin else rel
    ext = os.path.splitext(rel.lower())[1]
    if ext in MEDIA_EXTS or is_binary(data):
        if not scan_media(rel, data[:MAX_MEDIA], where, rep, cfg) and is_binary(data) and full:
            rep.add("INFO", "binary-file", where, "binary file of unknown type: check it by hand")
        return
    text = data[:MAX_TEXT].decode("utf-8", "replace")
    if len(data) > MAX_TEXT:
        rep.add("WARN", "large-text", where, f"only the first {MAX_TEXT} bytes were scanned")
    scan_text(text, rel, rep, cfg, ext=ext, origin=origin, full=full)
    if ext == ".svg" and full:
        if re.search(r"<metadata\b", text):
            rep.add("WARN", "svg-metadata", where, "SVG <metadata> block: check or remove it")
        if re.search(r"sodipodi:docname|inkscape:export-filename", text):
            rep.add("WARN", "svg-metadata", where, "Inkscape file or export names: remove them")
        if re.search(r"<script\b|\son[a-z]+\s*=", text, re.I):
            rep.add("WARN", "svg-active", where, "SVG with script or event handlers")


# ------------------------------------------------------------------- git

def git(root: Path, *args, input_bytes=None, timeout=180) -> subprocess.CompletedProcess:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    return subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-c", "core.quotepath=off", "-C", str(root), *args],
        input=input_bytes, capture_output=True, timeout=timeout, env=env)


def git_root(root: Path):
    if not (root / ".git").exists() or not shutil.which("git"):
        return None
    r = git(root, "rev-parse", "--show-toplevel")
    if r.returncode != 0:
        return None
    return Path(r.stdout.decode().strip()).resolve()


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
        check_name(rel, rep, where)
        if stat.S_ISLNK(st.st_mode):
            target = os.readlink(full)
            resolved = (full.parent / target).resolve()
            try:
                resolved.relative_to(root.resolve())
                rep.add("WARN", "symlink", where, f"symlink to {clean(target, 60)} (inside the repo)")
            except ValueError:
                rep.add("FAIL", "symlink", where,
                        f"symlink points outside the repo: {clean(target, 60)}")
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        if st.st_size > FAIL_SIZE:
            rep.add("FAIL", "large-file", where, f"{st.st_size // 1_000_000} MB: too big for a skill repo")
        elif st.st_size > WARN_SIZE:
            rep.add("WARN", "large-file", where, f"{st.st_size // 1_000_000} MB: is it needed?")
        with open(full, "rb") as fh:
            data = fh.read(MAX_MEDIA)
        if st.st_size <= MAX_MEDIA:
            shas.add(git_blob_sha(data))
        scan_bytes(rel, data, rep, cfg, origin="untracked" if untracked else "")
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
        check_name(rel, rep, f"{rel} (history {sha[:7]})")
        if size > MAX_MEDIA or total + size > MAX_HISTORY_TOTAL:
            skipped += 1
            continue
        total += size
        wanted.append(sha)
    if skipped:
        rep.add("WARN", "history-partial", ".", f"{skipped} large blobs in the history were not scanned")
    if not wanted:
        return
    batch = git(root, "cat-file", "--batch", input_bytes=("\n".join(wanted) + "\n").encode(),
                timeout=600)
    out = batch.stdout
    hist = Report()
    hist.CAP = 10 ** 9
    i = 0
    while i < len(out):
        nl = out.find(b"\n", i)
        if nl == -1:
            break
        header = out[i:nl].split()
        if len(header) != 3:
            break
        sha, size = header[0].decode(), int(header[2])
        data = out[nl + 1:nl + 1 + size]
        i = nl + 1 + size + 1
        rel = paths.get(sha, sha)
        scan_bytes(rel, data, hist, cfg, full=False,
                   origin=f"history {sha[:7]}, find it with git log --all --find-object={sha[:12]}")
    # The same leak repeated in every old version of a file is reported once.
    seen = set()
    for f in hist.findings:
        key = (f.severity, f.check, f.path.split(" (", 1)[0], f.message)
        if key not in seen:
            seen.add(key)
            rep.add(f.severity, f.check, f.path, f.message, f.line)


def scan_commits(root: Path, rep: Report, cfg):
    r = git(root, "log", "--all", "--format=%H%x1f%an <%ae>%x1f%cn <%ce>%x1f%B%x1e")
    if r.returncode != 0:
        return
    identities: dict = {}
    trailers = set()
    for rec in r.stdout.decode("utf-8", "replace").split("\x1e"):
        rec = rec.strip("\n")
        if not rec:
            continue
        parts = rec.split("\x1f")
        if len(parts) != 4:
            continue
        sha, author, committer, body = parts
        for ident in (author, committer):
            identities[ident] = identities.get(ident, 0) + 1
        for t in re.findall(r"(?im)^co-authored-by:\s*(.+)$", body):
            trailers.add(t.strip())
        scan_text(body, f"commit {sha[:7]}", rep, cfg, origin="message", full=False)
    allowed = set(cfg["author_identities"])
    for ident, n in sorted(identities.items()):
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

def run_gitleaks(root: Path, use_git: bool, rep: Report, files):
    """gitleaks on a copy of exactly the files a publish would include, plus the history."""
    exe = shutil.which("gitleaks")
    if not exe:
        rep.add("WARN", "gitleaks", ".", "gitleaks is not installed: install it and re-run, the built-in rules are a subset")
        return
    with tempfile.TemporaryDirectory() as td:
        copy = Path(td) / "tree"
        for rel, _u in files:
            src = root / rel
            if src.is_symlink() or not src.is_file():
                continue
            dest = copy / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest)
        copy.mkdir(exist_ok=True)
        modes = [("dir", ["dir", str(copy)], ["detect", "--no-git", "--source", str(copy)])]
        if use_git:
            modes.append(("git", ["git", str(root)], ["detect", "--source", str(root)]))
        for label, new, legacy in modes:
            report = os.path.join(td, f"{label}.json")
            common = ["--no-banner", "--redact", "--report-format", "json", "--report-path", report,
                      "--exit-code", "0"]
            res = subprocess.run([exe, *new, *common], capture_output=True, timeout=900)
            if res.returncode != 0 and b"unknown command" in res.stderr.lower():
                res = subprocess.run([exe, *legacy, *common], capture_output=True, timeout=900)
            if res.returncode != 0:
                rep.add("WARN", "gitleaks", ".", f"gitleaks {label} failed: {clean(res.stderr[-200:], 120)}")
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
                commit = f" commit {str(f.get('Commit'))[:7]}" if f.get("Commit") else ""
                rep.add("FAIL", f"gitleaks-{label}", file.replace(os.sep, "/"),
                        f"{clean(f.get('RuleID', 'secret'), 40)}{commit}", int(f.get("StartLine") or 0))


# --------------------------------------------------------- skill and repo

FRONTMATTER = re.compile(r"\A---\s*\n(.*?)\n---\s*(?:\n|\Z)", re.S)
LINK = re.compile(r"\[[^\]\n]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


def parse_frontmatter(text: str):
    m = FRONTMATTER.match(text)
    if not m:
        return None, text
    fields, key, block = {}, None, []
    for line in m.group(1).splitlines():
        km = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if km and not line.startswith((" ", "\t")):
            if key and block:
                fields[key] = " ".join(s.strip() for s in block).strip()
            key, val, block = km.group(1), km.group(2).strip(), []
            if val in (">", "|", ">-", "|-", ">+", "|+"):
                fields[key] = ""
            else:
                fields[key] = val.strip("\"'") if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'" else val
                key = None
        elif key:
            block.append(line)
    if key and block:
        fields[key] = " ".join(s.strip() for s in block).strip()
    return fields, text[m.end():]


def check_skill(root: Path, rep: Report, cfg):
    sk = root / "SKILL.md"
    if not sk.is_file() or sk.is_symlink():
        rep.add("FAIL", "skill-md", "SKILL.md", "missing: this is not a skill folder")
        return
    text = sk.read_text(encoding="utf-8", errors="replace")
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
        heads = re.findall(r"(?m)^#{2,3}\s+(.+)$", body)
        first = " ".join(heads[:4]).lower()
        if not re.search(r"intake|question|interview|domande|ask", first):
            rep.add("WARN", "skill-intake", "SKILL.md", "no intake step among the first headings: the skill should start by asking")


def check_links(root: Path, rep: Report, files):
    for rel, _u in files:
        # templates/ holds files meant for other repos: their links point there.
        if not rel.endswith(".md") or rel.startswith("templates/"):
            continue
        full = root / rel
        if full.is_symlink() or not full.is_file():
            continue
        text = full.read_text(encoding="utf-8", errors="replace")[:MAX_TEXT]
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
                rep.add("WARN", "link", rel, f"link leaves the repo: {clean(target, 60)}", line_of(text, m.start()))
                continue
            if not dest.exists():
                rep.add("WARN", "link", rel, f"broken relative link: {clean(target, 60)}", line_of(text, m.start()))


def check_repo_files(root: Path, rep: Report, cfg, files):
    names = {rel for rel, _ in files}
    for doc in sorted(n for n in names if "/" not in n and re.match(
            r"^(?:README|SECURITY|SKILL|LICEN[CS]E|CONTRIBUTING)(?:\.md|\.txt)?$", n)):
        full = root / doc
        if full.is_symlink() or not full.is_file():
            continue
        text = full.read_text(encoding="utf-8", errors="replace")[:MAX_TEXT]
        for m in PLACEHOLDER_LEFT.finditer(text):
            rep.add("FAIL", "placeholder", doc, f"template placeholder left: {m.group(0)}",
                    line_of(text, m.start()))
    lic = next((n for n in ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE") if n in names), None)
    if not lic:
        rep.add("FAIL", "license", ".", "no LICENSE file")
    else:
        text = (root / lic).read_text(encoding="utf-8", errors="replace")
        if "Permission is hereby granted, free of charge" not in text and "MIT License" not in text:
            rep.add("INFO", "license", lic, "not the MIT text: make sure the licence is the one agreed")
        holder = cfg.get("copyright_holder")
        if holder and holder not in text:
            rep.add("WARN", "license", lic, f"copyright holder {holder!r} not found")
    if "README.md" not in names:
        rep.add("FAIL", "readme", ".", "no README.md")
    else:
        heads = " ".join(re.findall(r"(?m)^#{1,3}\s+(.+)$",
                                    (root / "README.md").read_text(encoding="utf-8", errors="replace"))).lower()
        for want, rx in (("Install", r"install"), ("Usage", r"usage|how to use|use it"),
                         ("Security", r"security"), ("Licence", r"licen[cs]e")):
            if not re.search(rx, heads):
                rep.add("WARN", "readme", "README.md", f"no {want} section")
    if "SECURITY.md" not in names:
        rep.add("WARN", "security-md", ".", "no SECURITY.md (threat model and how to report)")
    else:
        st = (root / "SECURITY.md").read_text(encoding="utf-8", errors="replace").lower()
        if "report a vulnerability" not in st and "private vulnerability reporting" not in st:
            rep.add("WARN", "security-md", "SECURITY.md", "does not say how to report privately")
    if ".gitignore" not in names:
        rep.add("WARN", "gitignore", ".", "no .gitignore")
    if ".gitmodules" in names:
        rep.add("WARN", "submodules", ".gitmodules", "submodules pull in code that this scan does not see")
    workflows = [n for n in names if re.match(r"^\.github/workflows/[^/]+\.ya?ml$", n)]
    if not workflows:
        rep.add("WARN", "ci", ".", "no CI workflow in .github/workflows")
    for wf in workflows:
        check_workflow(root, wf, rep)
    for req in [n for n in names if re.match(r"^(?:.*/)?requirements[^/]*\.txt$", n)]:
        for i, line in enumerate((root / req).read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            s = line.split("#", 1)[0].strip()
            if s and not s.startswith("-") and "==" not in s and " @ " not in s:
                rep.add("WARN", "unpinned-dependency", req, f"not pinned with ==: {clean(s, 50)}", i)
    for pkg in [n for n in names if n.endswith("package.json") and "node_modules/" not in n]:
        folder = pkg[: -len("package.json")]
        if not any(folder + lock in names for lock in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")):
            rep.add("WARN", "unpinned-dependency", pkg, "no lockfile next to package.json")


USES = re.compile(r"(?m)^\s*-?\s*uses:\s*['\"]?([^\s'\"#]+)")


def check_workflow(root: Path, wf: str, rep: Report):
    text = (root / wf).read_text(encoding="utf-8", errors="replace")
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
    if re.search(r"(?m)^\s*pull_request_target\s*:|\bpull_request_target\b", text):
        rep.add("FAIL", "ci-trigger", wf, "pull_request_target runs fork code with secrets")
    if not re.search(r"(?m)^permissions\s*:", text):
        rep.add("WARN", "ci-permissions", wf, "no top-level permissions (use contents: read)")
    if re.search(r"permissions\s*:\s*write-all", text):
        rep.add("FAIL", "ci-permissions", wf, "permissions: write-all")
    if "${{ secrets." in text.replace("${{secrets.", "${{ secrets."):
        rep.add("WARN", "ci-secrets", wf, "uses repository secrets: a skill CI should not need any")
    if n_checkout and text.count("persist-credentials: false") < n_checkout:
        rep.add("WARN", "ci-credentials", wf, "checkout without persist-credentials: false")


# --------------------------------------------------------------- main scan

def scan(root: Path, cfg, *, history=True, gitleaks=True) -> Report:
    rep = Report()
    root = root.resolve()
    top = git_root(root)
    use_git = top is not None and top == root
    if top is not None and top != root:
        rep.add("WARN", "git", ".", f"folder is inside another repo ({clean(top, 60)}): history not scanned; stage it in its own folder")
    elif top is None:
        rep.add("INFO", "git", ".", "not a git repo yet: history checks skipped")
    n_terms = len(cfg["_terms"])
    if cfg.get("_source"):
        rep.add("INFO", "config", ".", f"owner config {cfg['_source']}, {n_terms} private terms")
    else:
        rep.add("WARN", "config", ".", "no owner config.json: commit identities are not checked")
    if not n_terms:
        rep.add("WARN", "config", ".", "no private terms loaded: names of people, clients and "
                "private projects are not checked (see README, private settings)")
    files = list_files(root, use_git, Report())
    shas = scan_tree(root, use_git, rep, cfg)
    check_skill(root, rep, cfg)
    check_repo_files(root, rep, cfg, files)
    check_links(root, rep, files)
    if use_git and history:
        scan_history(root, rep, cfg, shas)
        scan_commits(root, rep, cfg)
    if gitleaks:
        run_gitleaks(root, use_git, rep, files)
    return rep.finish()


def print_report(rep: Report, root: Path, as_json: bool):
    summary = {s: rep.count(s) for s in SEVERITIES}
    if as_json:
        print(json.dumps({"version": VERSION, "root": str(root), "summary": summary,
                          "findings": [asdict(f) for f in rep.findings]}, indent=2))
        return
    for f in rep.findings:
        loc = f"{f.path}:{f.line}" if f.line else f.path
        print(f"{f.severity:4}  {f.check:22} {loc}  {f.message}")
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


JPEG_DROP = {0xE1, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEF, 0xFE}


def strip_jpeg(data: bytes):
    """Drops APP1 and APP3-APP13, APP15 and comments; keeps JFIF, ICC (APP2), Adobe (APP14)."""
    out = [b"\xff\xd8"]
    removed = []
    for marker, start, end, _payload in jpeg_segments(data):
        if marker == 0xDA:
            out.append(data[start:])
            return b"".join(out), removed
        if marker in JPEG_DROP:
            removed.append(f"APP{marker - 0xE0}" if marker != 0xFE else "COM")
        else:
            out.append(data[start:end])
    raise ValueError("no image data found (not a complete JPEG)")


def strip_png(data: bytes):
    out = [PNG_SIG]
    removed = []
    seen_end = False
    for ctype, start, end, _payload in png_chunks(data):
        if ctype in PNG_META:
            removed.append(ctype.decode())
        else:
            out.append(data[start:end])
        if ctype == b"IEND":
            seen_end = True
    if not seen_end:
        raise ValueError("no IEND chunk (truncated PNG)")
    return b"".join(out), removed


def strip_file(path: Path, force=False) -> str:
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise ValueError("refusing a symlink")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError("not a regular file")
    if st.st_size > MAX_MEDIA:
        raise ValueError("file too large")
    data = path.read_bytes()
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
            print(f"not a folder: {root}", file=sys.stderr)
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
            print(f"{f}: {strip_file(Path(f), force=args.force)}")
        except (ValueError, OSError) as exc:
            print(f"{f}: NOT stripped, {exc}", file=sys.stderr)
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
