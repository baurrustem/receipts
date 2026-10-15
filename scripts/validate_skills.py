#!/usr/bin/env python3
"""Validate agent skill folders: Agent Skills spec + a safety baseline.

Usage:
  python3 scripts/validate_skills.py                  # every <repo>/skills/<name>/ except _template
  python3 scripts/validate_skills.py PATH [PATH ...]  # a repo root, a skills/ dir, or one skill dir
Options:
  --include-template   also validate skills/_template (its name need not match the folder)
  --json               machine-readable report on stdout
  --strict             treat warnings as errors

Exit codes: 0 = no errors, 1 = errors (or warnings with --strict), 2 = usage problem.
Stdlib only (Python 3.9+). Nothing here touches the network.
"""
from __future__ import annotations

import argparse
import bisect
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

# --- spec limits (https://agentskills.io/specification) ---------------------------------
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
MAX_NAME = 64
MAX_DESCRIPTION = 1024
MAX_COMPATIBILITY = 500
MAX_BODY_LINES = 500
ALLOWED_KEYS = ("name", "description", "license", "compatibility", "metadata", "allowed-tools")
TEMPLATE_DIR = "_template"

# --- safety baseline --------------------------------------------------------------------
LARGE_FILE_BYTES = 1024 * 1024
MAX_SCAN_BYTES = 8 * 1024 * 1024
BINARY_EXTS = frozenset({".so", ".dylib", ".dll", ".exe", ".pyc", ".pyo", ".class"})
# Media is allowed in assets/ only when the bytes match the extension.
MEDIA_MAGIC: dict[str, tuple[bytes, ...]] = {
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".gif": (b"GIF87a", b"GIF89a"),
    ".webp": (b"RIFF",),
    ".pdf": (b"%PDF-",),
    ".ico": (b"\x00\x00\x01\x00",),
    ".woff": (b"wOFF",),
    ".woff2": (b"wOF2",),
    ".ttf": (b"\x00\x01\x00\x00", b"true"),
    ".otf": (b"OTTO",),
}
TEST_FILE_RES = (
    re.compile(r"^conftest\.py$"),
    re.compile(r"^test_.*\.py$"),
    re.compile(r"^.+_test\.py$"),
    re.compile(r"^.+\.(test|spec)\.[cm]?[jt]sx?$"),
)
SECRET_FILE_RES = (
    re.compile(r"^\.env(\..*)?$"),
    re.compile(r"^\.(npmrc|pypirc|netrc)$"),
    re.compile(r"^id_(rsa|dsa|ecdsa|ed25519)$"),
)
INSTALL_HOOK_KEYS = ("preinstall", "install", "postinstall", "prepare")
OS_JUNK_FILES = frozenset({".DS_Store", "Thumbs.db", "desktop.ini"})

# Characters that can hide or reorder text for a human reviewer.
HIDDEN_ERROR = {cp: name for cp, name in [
    (0x200B, "ZERO WIDTH SPACE"),
    (0x202A, "LEFT-TO-RIGHT EMBEDDING"),
    (0x202B, "RIGHT-TO-LEFT EMBEDDING"),
    (0x202C, "POP DIRECTIONAL FORMATTING"),
    (0x202D, "LEFT-TO-RIGHT OVERRIDE"),
    (0x202E, "RIGHT-TO-LEFT OVERRIDE"),
    (0x2066, "LEFT-TO-RIGHT ISOLATE"),
    (0x2067, "RIGHT-TO-LEFT ISOLATE"),
    (0x2068, "FIRST STRONG ISOLATE"),
    (0x2069, "POP DIRECTIONAL ISOLATE"),
    (0x034F, "COMBINING GRAPHEME JOINER"),
    (0x061C, "ARABIC LETTER MARK"),
    (0x115F, "HANGUL CHOSEONG FILLER"),
    (0x1160, "HANGUL JUNGSEONG FILLER"),
    (0x17B4, "KHMER VOWEL INHERENT AQ"),
    (0x17B5, "KHMER VOWEL INHERENT AA"),
    (0x180B, "MONGOLIAN FREE VARIATION SELECTOR ONE"),
    (0x180C, "MONGOLIAN FREE VARIATION SELECTOR TWO"),
    (0x180D, "MONGOLIAN FREE VARIATION SELECTOR THREE"),
    (0x180E, "MONGOLIAN VOWEL SEPARATOR"),
    (0x180F, "MONGOLIAN FREE VARIATION SELECTOR FOUR"),
    (0x3164, "HANGUL FILLER"),
    (0xFFA0, "HALFWIDTH HANGUL FILLER"),
]}
HIDDEN_WARN = {cp: name for cp, name in [
    (0x200C, "ZERO WIDTH NON-JOINER"),
    (0x200D, "ZERO WIDTH JOINER"),
    (0x200E, "LEFT-TO-RIGHT MARK"),
    (0x200F, "RIGHT-TO-LEFT MARK"),
    (0x2060, "WORD JOINER"),
    (0x2061, "FUNCTION APPLICATION"),
    (0x2062, "INVISIBLE TIMES"),
    (0x2063, "INVISIBLE SEPARATOR"),
    (0x2064, "INVISIBLE PLUS"),
    (0xFEFF, "ZERO WIDTH NO-BREAK SPACE (BOM)"),
    (0x00AD, "SOFT HYPHEN"),
]}
HIDDEN_RE = re.compile(
    "[" + "".join(chr(c) for c in sorted(set(HIDDEN_ERROR) | set(HIDDEN_WARN))) + "\U000E0000-\U000E007F]"
)
# Variation selectors can smuggle a whole hidden message after one emoji (one selector per byte).
# A single U+FE0E/U+FE0F after a visible character is normal emoji/text presentation; a run of two
# or more, or any supplement selector (U+E0100-E01EF), is not.
VS_RUN_RE = re.compile("[\uFE00-\uFE0F\U000E0100-\U000E01EF]{2,}|[\U000E0100-\U000E01EF]")

PIPE_TO_SHELL_RES = (
    # curl ... | sh, wget -qO- ... | sudo bash, curl ... | tee x | sh
    re.compile(
        r"\b(?:curl|wget)\b[^\n|]*(?:\|[^\n|]*)*?\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+(?:\S+=\S*\s+)*)?"
        r"(?:/usr/local/bin/|/usr/bin/|/bin/)?(?:ba|z|da|k|fi)?sh\b",
        re.IGNORECASE,
    ),
    # sh -c "$(curl ...)"
    re.compile(r"\b(?:ba|z|da|k)?sh\s+(?:-\S+\s+)*[\"']?\$\(\s*(?:curl|wget)\b", re.IGNORECASE),
    # bash <(curl ...)
    re.compile(r"\b(?:ba|z|da|k)?sh\s+<\(\s*(?:curl|wget)\b", re.IGNORECASE),
    # curl ... | python3 -   (and node, perl, ruby, php, deno, bun, pwsh)
    re.compile(
        r"\b(?:curl|wget)\b[^\n|]*(?:\|[^\n|]*)*?\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+(?:\S+=\S*\s+)*)?"
        r"(?:\S*/)?(?:python[0-9.]*|node|perl|ruby|php|deno|bun|pwsh|powershell)\b",
        re.IGNORECASE,
    ),
    # python3 <(curl ...), python3 -c "$(curl ...)"
    re.compile(r"\b(?:python[0-9.]*|node|perl|ruby)\s+(?:-\S+\s+)*(?:<\(|[\"']?\$\()\s*(?:curl|wget)\b",
               re.IGNORECASE),
    # PowerShell: irm ... | iex, iex (irm ...), iex (New-Object Net.WebClient).DownloadString(...)
    re.compile(r"\b(?:irm|iwr|Invoke-RestMethod|Invoke-WebRequest)\b[^\n|]*\|\s*(?:iex|Invoke-Expression)\b",
               re.IGNORECASE),
    re.compile(r"\b(?:iex|Invoke-Expression)\b[^\n]*\b(?:irm|iwr|Invoke-RestMethod|Invoke-WebRequest|DownloadString)\b",
               re.IGNORECASE),
    # echo <blob> | base64 -d | sh
    re.compile(
        r"\bbase64\s+(?:-\S+\s+)*(?:-d|-D|--decode)\b[^\n|]*(?:\|[^\n|]*)*?\|\s*(?:sudo\s+(?:-\S+\s+)*)?"
        r"(?:\S*/)?(?:(?:ba|z|da|k|fi)?sh|python[0-9.]*|node|perl|ruby)\b",
        re.IGNORECASE,
    ),
)
# curl -o x.sh URL ... && bash x.sh  (download to a file, then run it)
DOWNLOAD_TO_FILE_RE = re.compile(
    r"\b(?:curl|wget)\b[^\n]*?\s(?:-o|-O|--output|--output-document)(?:[ \t]+|=)[\"']?([^\s;&|)\"']+)", re.IGNORECASE)
# Claude Code runs !`cmd` (and ```! blocks) when a skill loads, before the model sees the text.
DYNAMIC_SHELL_RE = re.compile(r"(?:^|(?<=\s))!`[^`\n]+`|^[ \t]*```!", re.MULTILINE)
# Package runners besides npx/uvx; warned like npx/uvx when unpinned.
EXTRA_RUNNER_RE = re.compile(
    r"(?<![\w./@-])(pnpm[ \t]+dlx|yarn[ \t]+dlx|bunx|bun[ \t]+x|pipx[ \t]+run)[ \t]+([^\n`|;&)\"'<>]*)")
# allowed-tools in a published skill pre-approves commands for everyone who installs it.
ALLOWED_TOOL_RE = re.compile(r"([A-Za-z_][\w.-]*)(?:\(([^)]*)\))?")
RISKY_COMMAND_SAMPLES = (
    "git push", "git push origin main", "git -C repo push --force", "gh repo create",
    "gh repo create me/x --public", "gh release create v1.0.0", "gh pr create --fill",
    "gh issue create -t x", "gh issue comment 1 -b x", "gh api repos/o/r/issues -f title=x",
    "gh gist create notes.md", "npm publish", "pnpm publish", "curl -X POST -d @data https://collector.example",
    "rm -rf ~", "python3 -c 'import os'", "bash -c id", "sh -c id",
)

RUNNER_RE = re.compile(r"(?<![\w./@-])(npx|uvx)[ \t]+([^\n`|;&)\"'<>]*)")
RUNNER_PACKAGE_FLAGS = {"npx": {"-p", "--package"}, "uvx": {"--from"}}
RUNNER_EXTRA_PACKAGE_FLAGS = {"npx": set(), "uvx": {"--with"}}
RUNNER_VALUE_FLAGS = {
    "npx": {"-c", "--call", "--registry", "--cache", "--userconfig", "-w", "--workspace"},
    "uvx": {"-p", "--python", "--index", "--index-url", "--extra-index-url", "--default-index", "-i",
            "--constraint", "-c", "--cache-dir", "--directory", "--project", "--config-file",
            "--env-file", "--with-editable", "--with-requirements"},
}
PACKAGE_TOKEN_RE = re.compile(r"^[@A-Za-z0-9][\w.@/=<>~^+!-]*$")

URL_RE = re.compile(r"https?://[^\s<>\"'`)\]}|\\]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})(?![\w-])", re.IGNORECASE)
IGNORED_HOSTS = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1", "example.com", "example.org", "example.net"})
IGNORED_HOST_SUFFIXES = (".example", ".test", ".invalid", ".localhost", ".example.com", ".example.org", ".example.net")
DISCLOSURE_HEADING_RE = re.compile(r"^(#{1,6})[ \t]+What it runs\b.*$", re.IGNORECASE | re.MULTILINE)
HEADING_RE = re.compile(r"^(#{1,6})[ \t]+\S", re.MULTILINE)
TODO_RE = re.compile(r"\bTODO\b")


# --- report model -----------------------------------------------------------------------
@dataclass
class Issue:
    level: str  # "error" | "warning"
    code: str
    message: str
    file: str = ""
    line: int | None = None


@dataclass
class SkillResult:
    skill: str
    path: str
    template: bool = False
    issues: list[Issue] = field(default_factory=list)

    def add(self, level: str, code: str, message: str, file: str = "", line: int | None = None) -> None:
        self.issues.append(Issue(level, code, message, file, line))

    @property
    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self) -> list[Issue]:
        return [i for i in self.issues if i.level == "warning"]


@dataclass
class Report:
    skills: list[SkillResult] = field(default_factory=list)
    repo: list[Issue] = field(default_factory=list)

    @property
    def error_count(self) -> int:
        return sum(len(s.errors) for s in self.skills) + sum(1 for i in self.repo if i.level == "error")

    @property
    def warning_count(self) -> int:
        return sum(len(s.warnings) for s in self.skills) + sum(1 for i in self.repo if i.level == "warning")

    def ok(self, strict: bool = False) -> bool:
        return self.error_count == 0 and (not strict or self.warning_count == 0)

    def to_dict(self, strict: bool = False) -> dict[str, Any]:
        return {
            "ok": self.ok(strict),
            "strict": strict,
            "summary": {"skills": len(self.skills), "errors": self.error_count, "warnings": self.warning_count},
            "skills": [
                {
                    "skill": s.skill,
                    "path": s.path,
                    "template": s.template,
                    "errors": [asdict(i) for i in s.errors],
                    "warnings": [asdict(i) for i in s.warnings],
                }
                for s in self.skills
            ],
            "repo": [asdict(i) for i in self.repo],
        }


# --- minimal YAML subset (frontmatter only) ---------------------------------------------
class FrontmatterError(ValueError):
    def __init__(self, message: str, line: int | None = None):
        super().__init__(message)
        self.line = line


_KEY_RE = re.compile(r"^([A-Za-z0-9_][A-Za-z0-9_.\-]*|\"[^\"]*\"|'[^']*')[ \t]*:(?:[ \t]+(.*)|[ \t]*)$")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _strip_comment(s: str) -> str:
    """Drop a trailing ' # comment' from a plain scalar."""
    m = re.search(r"(^|[ \t])#", s)
    return s[: m.start()] if m else s


class _YamlSubset:
    """Parses the YAML that SKILL.md frontmatter uses in practice.

    Supports block mappings, block sequences of scalars or mappings, plain / quoted / block
    scalars (| and >), and JSON-style flow collections. Rejects constructs that strict YAML
    parsers (js-yaml, PyYAML) reject, such as ': ' inside a plain scalar.
    """

    def __init__(self, text: str, first_line: int = 2):
        self.lines = text.split("\n")
        self.i = 0
        self.first_line = first_line

    def lineno(self, idx: int | None = None) -> int:
        return (self.i if idx is None else idx) + self.first_line

    def _skip_blank(self) -> None:
        while self.i < len(self.lines):
            s = self.lines[self.i].strip()
            if s and not s.startswith("#"):
                return
            self.i += 1

    def parse(self) -> dict[str, Any]:
        for idx, line in enumerate(self.lines):
            if "\t" in line[: len(line) - len(line.lstrip(" \t"))]:
                raise FrontmatterError("tab used for indentation", self.lineno(idx))
        self._skip_blank()
        if self.i >= len(self.lines):
            return {}
        if _indent(self.lines[self.i]) != 0:
            raise FrontmatterError("frontmatter must start at column 0", self.lineno())
        value = self._block(0)
        self._skip_blank()
        if self.i < len(self.lines):
            raise FrontmatterError("could not parse line", self.lineno())
        if not isinstance(value, dict):
            raise FrontmatterError("frontmatter must be a mapping of key: value pairs", self.first_line)
        return value

    def _block(self, indent: int) -> Any:
        self._skip_blank()
        line = self.lines[self.i]
        content = line[indent:]
        if content == "-" or content.startswith("- "):
            return self._seq(indent)
        return self._map(indent)

    def _map(self, indent: int) -> dict[str, Any]:
        out: dict[str, Any] = {}
        while True:
            self._skip_blank()
            if self.i >= len(self.lines):
                return out
            line = self.lines[self.i]
            cur = _indent(line)
            if cur < indent:
                return out
            if cur > indent:
                raise FrontmatterError("unexpected indentation", self.lineno())
            m = _KEY_RE.match(line[cur:])
            if not m:
                if line[cur:].startswith("- "):
                    return out
                raise FrontmatterError("expected 'key: value'", self.lineno())
            key = m.group(1)
            if key[0] in "\"'":
                key = key[1:-1]
            if key in out:
                raise FrontmatterError(f"duplicate key '{key}'", self.lineno())
            key_line = self.i
            self.i += 1
            out[key] = self._value(m.group(2) or "", indent, key_line)

    def _seq(self, indent: int) -> list[Any]:
        items: list[Any] = []
        while True:
            self._skip_blank()
            if self.i >= len(self.lines):
                return items
            line = self.lines[self.i]
            cur = _indent(line)
            content = line[cur:]
            if cur != indent or not (content == "-" or content.startswith("- ")):
                if cur > indent:
                    raise FrontmatterError("unexpected indentation in list", self.lineno())
                return items
            rest = content[1:].strip()
            if rest and _KEY_RE.match(rest):
                # "- key: value" starts a mapping item; re-read it as a mapping indented past the dash.
                pad = cur + (len(content) - len(content[1:].lstrip(" ")))
                self.lines[self.i] = " " * pad + rest
                items.append(self._map(pad))
                continue
            item_line = self.i
            self.i += 1
            items.append(self._value(rest, indent, item_line))

    def _value(self, rest: str, parent_indent: int, line_idx: int) -> Any:
        raw = rest.strip()
        if raw == "" or raw.startswith("#"):
            self._skip_blank()
            if self.i < len(self.lines):
                nxt = self.lines[self.i]
                nind = _indent(nxt)
                if nind > parent_indent:
                    return self._block(nind)
                if nind == parent_indent and (nxt[nind:] == "-" or nxt[nind:].startswith("- ")):
                    return self._seq(nind)
            return None
        first = raw[0]
        if first in "|>":
            return self._block_scalar(raw, parent_indent, line_idx)
        if first in "[{":
            return self._flow(raw, line_idx)
        if first in "\"'":
            return self._quoted(rest.lstrip(), parent_indent, line_idx)
        if first in "@`":
            raise FrontmatterError(f"a plain value cannot start with '{first}'; quote it", self.lineno(line_idx))
        if first in "*&!%":
            raise FrontmatterError(f"YAML anchors/aliases/tags ('{first}') are not supported; quote the value",
                                   self.lineno(line_idx))
        parts = [_strip_comment(raw).strip()]
        # Multi-line plain scalar: continuation lines are indented deeper than the key.
        while self.i < len(self.lines):
            nxt = self.lines[self.i]
            if not nxt.strip():
                break
            if _indent(nxt) <= parent_indent or nxt.strip().startswith("#"):
                break
            parts.append(_strip_comment(nxt.strip()).strip())
            self.i += 1
        text = " ".join(p for p in parts if p)
        if re.search(r":(\s|$)", text):
            raise FrontmatterError("plain value contains ': ' which strict YAML parsers reject; quote the value",
                                   self.lineno(line_idx))
        return _plain_scalar(text)

    def _quoted(self, s: str, parent_indent: int, line_idx: int) -> str:
        q = s[0]
        buf = s
        while True:
            end = _closing_quote(buf, q)
            if end is not None:
                tail = buf[end + 1:].strip()
                if tail and not tail.startswith("#"):
                    raise FrontmatterError("unexpected text after quoted value", self.lineno(line_idx))
                inner = buf[1:end]
                break
            if self.i >= len(self.lines) or (self.lines[self.i].strip() and _indent(self.lines[self.i]) <= parent_indent):
                raise FrontmatterError("unterminated quoted value", self.lineno(line_idx))
            buf = buf + "\n" + self.lines[self.i].strip()
            self.i += 1
        if "\n" in inner:  # folded like YAML: single newlines become spaces
            inner = re.sub(r"[ \t]*\n[ \t]*", " ", inner)
        if q == "'":
            return inner.replace("''", "'")
        try:
            return json.loads('"' + inner + '"')
        except ValueError:
            return inner.replace('\\"', '"').replace("\\\\", "\\")

    def _block_scalar(self, header: str, parent_indent: int, line_idx: int) -> str:
        m = re.match(r"^([|>])([+-]?)(\d?)([+-]?)\s*(#.*)?$", header)
        if not m:
            raise FrontmatterError("bad block scalar header", self.lineno(line_idx))
        style, chomp = m.group(1), (m.group(2) or m.group(4))
        explicit = int(m.group(3)) if m.group(3) else None
        block_indent = parent_indent + explicit if explicit else None
        lines: list[str] = []
        while self.i < len(self.lines):
            line = self.lines[self.i]
            if not line.strip():
                lines.append("")
                self.i += 1
                continue
            ind = _indent(line)
            if ind <= parent_indent:
                break
            if block_indent is None:
                block_indent = ind
            if ind < block_indent:
                break
            lines.append(line[block_indent:])
            self.i += 1
        trailing = 0
        while lines and lines[-1] == "":
            lines.pop()
            trailing += 1
        if style == "|":
            text = "\n".join(lines)
        else:
            text, para = "", []
            for ln in lines:
                if ln == "":
                    text += (" ".join(para) + "\n") if para else "\n"
                    para = []
                else:
                    para.append(ln)
            text += " ".join(para)
        if chomp == "-":
            return text
        if chomp == "+":
            return text + "\n" * (trailing + 1)
        return text + "\n" if text else text

    def _flow(self, raw: str, line_idx: int) -> Any:
        s = _strip_comment(raw).strip() if not raw.rstrip().endswith(("]", "}")) else raw.strip()
        try:
            return json.loads(s)
        except ValueError:
            pass
        if s.startswith("[") and s.endswith("]"):
            inner = s[1:-1].strip()
            if not inner:
                return []
            if "[" in inner or "{" in inner:
                raise FrontmatterError("nested flow collections are not supported", self.lineno(line_idx))
            return [_unquote(x.strip()) for x in inner.split(",") if x.strip()]
        raise FrontmatterError("unsupported flow collection; use JSON syntax or block style", self.lineno(line_idx))


def _closing_quote(s: str, q: str) -> int | None:
    i = 1
    while i < len(s):
        c = s[i]
        if q == '"' and c == "\\":
            i += 2
            continue
        if c == q:
            if q == "'" and i + 1 < len(s) and s[i + 1] == "'":
                i += 2
                continue
            return i
        i += 1
    return None


def _unquote(s: str) -> Any:
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return _plain_scalar(s)


def _plain_scalar(s: str) -> Any:
    low = s.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "~", ""):
        return None
    if re.fullmatch(r"[-+]?\d+", s):
        return int(s)
    if re.fullmatch(r"[-+]?(\d+\.\d*|\.\d+)([eE][-+]?\d+)?", s):
        return float(s)
    return s


def parse_frontmatter(text: str) -> tuple[dict[str, Any] | None, str, int, str | None, int | None]:
    """Split SKILL.md into (frontmatter, body, body_first_line, error, error_line)."""
    if text.startswith("﻿"):
        text = text[1:]
    lines = text.split("\n")
    if not lines or lines[0].rstrip() != "---":
        return None, text, 1, "SKILL.md must start with '---' YAML frontmatter", 1
    for idx in range(1, len(lines)):
        if lines[idx].rstrip() in ("---", "..."):
            fm_text = "\n".join(lines[1:idx])
            body = "\n".join(lines[idx + 1:])
            try:
                data = _YamlSubset(fm_text, first_line=2).parse()
            except FrontmatterError as e:
                return None, body, idx + 2, f"frontmatter: {e}", e.line
            return data, body, idx + 2, None, None
    return None, text, 1, "frontmatter is not closed with '---'", 1


# --- helpers ----------------------------------------------------------------------------
class _LineIndex:
    def __init__(self, text: str):
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def line_col(self, offset: int) -> tuple[int, int]:
        idx = bisect.bisect_right(self.starts, offset) - 1
        return idx + 1, offset - self.starts[idx] + 1


def _rel(path: Path, base: Path) -> str:
    try:
        return os.path.relpath(path, base).replace(os.sep, "/")
    except ValueError:
        return str(path)


def _host_of(url: str) -> str | None:
    url = url.rstrip(".,;:!?*_~")
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    if not host or any(c in host for c in "{}<>$%"):
        return None
    host = host.lower().rstrip(".")
    if "." not in host and host not in IGNORED_HOSTS:
        return None
    return host


def _host_ignored(host: str) -> bool:
    return host in IGNORED_HOSTS or host.endswith(IGNORED_HOST_SUFFIXES)


def _host_declared(host: str, declared: set[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in declared)


def disclosure_sections(markdown: str) -> list[tuple[int, int]]:
    """Return (start, end) offsets of every 'What it runs / sends / fetches' section."""
    spans = []
    for m in DISCLOSURE_HEADING_RE.finditer(markdown):
        level = len(m.group(1))
        end = len(markdown)
        for h in HEADING_RE.finditer(markdown, m.end()):
            if len(h.group(1)) <= level:
                end = h.start()
                break
        spans.append((m.start(), end))
    return spans


def declared_hosts(section_text: str) -> set[str]:
    hosts = set()
    for u in URL_RE.findall(section_text):
        h = _host_of(u)
        if h:
            hosts.add(h)
    for d in DOMAIN_RE.findall(section_text):
        hosts.add(d.lower().rstrip("."))
    return hosts


def _runner_specs(cmd: str, argstr: str) -> list[str]:
    toks = argstr.split()
    specs: list[str] = []
    explicit_package = False
    i = 0
    while i < len(toks):
        t = toks[i]
        if t == "--":
            break
        if t.startswith("-") and len(t) > 1:
            flag, eq, val = t.partition("=")
            takes_pkg = flag in RUNNER_PACKAGE_FLAGS[cmd] or flag in RUNNER_EXTRA_PACKAGE_FLAGS[cmd]
            if takes_pkg:
                v = val if eq else (toks[i + 1] if i + 1 < len(toks) else "")
                if v:
                    specs.append(v)
                if flag in RUNNER_PACKAGE_FLAGS[cmd]:
                    explicit_package = True
                i += 1 if eq else 2
                continue
            if flag in RUNNER_VALUE_FLAGS[cmd] and not eq:
                i += 2
                continue
            i += 1
            continue
        if not explicit_package:
            specs.append(t)
        break
    return specs


def _is_pinned(cmd: str, spec: str) -> bool | None:
    """True/False for registry packages; None when the token is not a package (path, URL, placeholder)."""
    spec = spec.strip("`'\",")
    if not spec or spec[0] in ".~/$<{[" or "://" in spec or not PACKAGE_TOKEN_RE.match(spec):
        return None
    if cmd == "npx":
        body = spec[1:] if spec.startswith("@") else spec
        if "@" not in body:
            return False
        return bool(re.match(r"v?\d", body.split("@", 1)[1]))
    return bool(re.search(r"(==|@)v?\d", spec))


def _extra_runner_spec(argstr: str) -> str:
    toks = argstr.split()
    i = 0
    while i < len(toks):
        t = toks[i]
        if t in ("--spec", "-p", "--package"):
            return toks[i + 1] if i + 1 < len(toks) else ""
        if t.startswith(("--spec=", "--package=")):
            return t.split("=", 1)[1]
        if t.startswith("-"):
            i += 1
            continue
        return t
    return ""


def _download_then_run(text: str) -> list[int]:
    hits = []
    for m in DOWNLOAD_TO_FILE_RE.finditer(text):
        target = m.group(1)
        if target in ("-", "/dev/null", "/dev/stdout"):
            continue
        name = re.escape(target.rsplit("/", 1)[-1])
        if not name:
            continue
        exec_re = re.compile(
            r"(?:\b(?:(?:ba|z|da|k)?sh|python[0-9.]*|node|perl|ruby|source)\s+(?:-\S+\s+)*[\"']?(?:\S*/)?" + name
            + r"|\bchmod\s+(?:-\S+\s+)*\S*x\S*\s+[\"']?(?:\S*/)?" + name
            + r"|(?<![\w.])\./" + name + r")(?![\w.-])")
        if exec_re.search(text, m.end()):
            hits.append(m.start())
    return hits


# --- per-skill validation ---------------------------------------------------------------
def _check_frontmatter(res: SkillResult, fm: dict[str, Any], folder: str, md_rel: str, is_template: bool) -> None:
    unknown = [k for k in fm if k not in ALLOWED_KEYS]
    for k in unknown:
        res.add("error", "frontmatter-key",
                f"frontmatter key '{k}' is not in the Agent Skills spec (allowed: {', '.join(ALLOWED_KEYS)})", md_rel)

    name = fm.get("name")
    if name is None or name == "":
        res.add("error", "name-missing", "frontmatter 'name' is required", md_rel)
    elif not isinstance(name, str):
        res.add("error", "name-format", "'name' must be a string", md_rel)
    else:
        if len(name) > MAX_NAME:
            res.add("error", "name-length", f"'name' is {len(name)} characters (max {MAX_NAME})", md_rel)
        if not NAME_RE.match(name):
            res.add("error", "name-format",
                    f"'name' {name!r} must match {NAME_RE.pattern} (lowercase letters, digits, single hyphens)", md_rel)
        if not is_template and name != folder:
            res.add("error", "name-mismatch", f"'name' {name!r} must equal the folder name {folder!r}", md_rel)

    desc = fm.get("description")
    if desc is None or (isinstance(desc, str) and not desc.strip()):
        res.add("error", "description-missing", "frontmatter 'description' is required and must be non-empty", md_rel)
    elif not isinstance(desc, str):
        res.add("error", "description-format", "'description' must be a string (quote it)", md_rel)
    elif len(desc) > MAX_DESCRIPTION:
        res.add("error", "description-length", f"'description' is {len(desc)} characters (max {MAX_DESCRIPTION})",
                md_rel)

    if "license" in fm and not isinstance(fm["license"], str):
        res.add("error", "license-format", "'license' must be a string", md_rel)

    if "compatibility" in fm:
        comp = fm["compatibility"]
        if not isinstance(comp, str) or not comp.strip():
            res.add("error", "compatibility-format", "'compatibility' must be a non-empty string", md_rel)
        elif len(comp) > MAX_COMPATIBILITY:
            res.add("error", "compatibility-length",
                    f"'compatibility' is {len(comp)} characters (max {MAX_COMPATIBILITY})", md_rel)

    if "metadata" in fm:
        meta = fm["metadata"]
        if not isinstance(meta, dict):
            res.add("error", "metadata-format", "'metadata' must be a mapping of key: value", md_rel)
        else:
            for k, v in meta.items():
                if k == "internal":
                    continue
                if not isinstance(v, str):
                    res.add("warning", "metadata-value",
                            f"metadata.{k} should be a string per the spec (quote it)", md_rel)
            if meta.get("internal") is True and not is_template:
                res.add("warning", "internal-flag",
                        "metadata.internal is true: the skills CLI hides this skill from normal installs", md_rel)

    if "allowed-tools" in fm:
        tools = fm["allowed-tools"]
        if isinstance(tools, list):
            res.add("warning", "allowed-tools-format",
                    "'allowed-tools' should be a space-separated string per the spec", md_rel)
        elif not isinstance(tools, str):
            res.add("error", "allowed-tools-format", "'allowed-tools' must be a string", md_rel)
        for problem in risky_allowed_tools(" ".join(map(str, tools)) if isinstance(tools, list) else tools):
            res.add("error", "allowed-tools-risky", problem, md_rel)


def _rule_regex(arg: str) -> re.Pattern:
    a = arg.strip()
    if a.endswith(":*"):          # legacy prefix syntax: Bash(git:*)
        a = a[:-2] + " *"
    return re.compile("^" + ".*".join(re.escape(part) for part in a.split("*")) + "$", re.S)


def risky_allowed_tools(tools: Any) -> list[str]:
    """Problems with an allowed-tools string: rules that pre-approve any shell command, any URL,
    or a publishing / arbitrary-code command for every user who installs the skill."""
    if not isinstance(tools, str):
        return []
    out: list[str] = []
    for m in ALLOWED_TOOL_RE.finditer(tools):
        name, arg = m.group(1), m.group(2)
        if name == "Bash":
            if arg is None or arg.strip() in ("", "*", ":*"):
                out.append(f"'{m.group(0)}' pre-approves every shell command for everyone who installs the skill")
                continue
            rx = _rule_regex(arg)
            hit = next((c for c in RISKY_COMMAND_SAMPLES if rx.match(c)), None)
            if hit:
                out.append(f"'{m.group(0)}' pre-approves commands like {hit!r} (publishing, deleting or "
                           "arbitrary code); list exact read-only commands instead")
        elif name == "WebFetch" and (arg is None or arg.strip() in ("", "*", "domain:*")):
            out.append(f"'{m.group(0)}' pre-approves fetching any URL; use WebFetch(domain:<host>)")
    return out


def validate_skill(skill_dir: Path, base: Path | None = None, *, is_template: bool | None = None) -> SkillResult:
    skill_dir = Path(skill_dir)
    base = Path(base) if base is not None else skill_dir.parent
    folder = skill_dir.name
    if is_template is None:
        is_template = folder == TEMPLATE_DIR
    res = SkillResult(skill=folder, path=_rel(skill_dir, base), template=is_template)
    skill_md = skill_dir / "SKILL.md"
    md_rel = _rel(skill_md, base)

    skill_md_text = ""
    body = ""
    body_first_line = 1
    entries = os.listdir(skill_dir) if skill_dir.is_dir() else []
    has_skill_md = "SKILL.md" in entries and skill_md.is_file()  # exact case, even on case-insensitive disks
    if not has_skill_md:
        alt = [n for n in entries if n.lower() == "skill.md"]
        hint = f" (found {alt[0]!r}; the file name must be exactly SKILL.md)" if alt else ""
        res.add("error", "missing-skill-md", "SKILL.md is missing" + hint, _rel(skill_dir, base))
    else:
        raw = skill_md.read_bytes()[:MAX_SCAN_BYTES]
        skill_md_text = raw.decode("utf-8", errors="replace")
        fm, body, body_first_line, err, err_line = parse_frontmatter(skill_md_text)
        if err:
            res.add("error", "frontmatter", err, md_rel, err_line)
        if fm is not None:
            _check_frontmatter(res, fm, folder, md_rel, is_template)
        body_lines = len(body.splitlines())
        if body_lines > MAX_BODY_LINES:
            res.add("error", "body-length",
                    f"SKILL.md body is {body_lines} lines (max {MAX_BODY_LINES}); move detail into references/",
                    md_rel)
        if not is_template and TODO_RE.search(skill_md_text):
            line = _LineIndex(skill_md_text).line_col(TODO_RE.search(skill_md_text).start())[0]
            res.add("warning", "todo-left", "SKILL.md still contains TODO placeholders", md_rel, line)

    # Disclosure: SKILL.md first, then any other Markdown file at the skill root.
    declared: set[str] = set()
    disclosure_spans: dict[Path, list[tuple[int, int]]] = {}
    md_candidates = [skill_md] if has_skill_md else []
    if skill_dir.is_dir():
        md_candidates += sorted(p for p in skill_dir.glob("*.md") if p.name != "SKILL.md" and p.is_file())
    for md in md_candidates:
        text = skill_md_text if md == skill_md else md.read_text("utf-8", errors="replace")
        spans = disclosure_sections(text)
        if spans:
            disclosure_spans[md] = spans
            for s, e in spans:
                declared |= declared_hosts(text[s:e])
    if not disclosure_spans:
        res.add("error", "missing-disclosure",
                "no 'What it runs / sends / fetches' section (SKILL.md or a Markdown file in the skill root)", md_rel)

    undeclared: dict[str, tuple[str, int, int]] = {}  # host -> (file, line, count)
    if skill_dir.is_dir():
        for path in _walk(skill_dir, res, base):
            _check_file(path, skill_dir, base, res, declared, disclosure_spans, undeclared)
    for host, (f, line, count) in sorted(undeclared.items()):
        more = f" ({count} references)" if count > 1 else ""
        res.add("warning", "undeclared-host",
                f"URL host '{host}' is not listed in the 'What it runs / sends / fetches' section{more}", f, line)
    return res


def _walk(skill_dir: Path, res: SkillResult, base: Path):
    root_real = os.path.realpath(skill_dir)
    for dirpath, dirnames, filenames in os.walk(skill_dir, followlinks=False):
        dirnames.sort()
        for d in list(dirnames):
            p = Path(dirpath) / d
            if p.is_symlink():
                dirnames.remove(d)
                _check_symlink(p, root_real, res, base)
            elif d == "node_modules":
                res.add("error", "vendored-deps", "node_modules/ must not ship inside a skill", _rel(p, base))
                dirnames.remove(d)
        for f in sorted(filenames):
            p = Path(dirpath) / f
            if p.is_symlink():
                _check_symlink(p, root_real, res, base)
                continue
            yield p


def _check_symlink(p: Path, root_real: str, res: SkillResult, base: Path) -> None:
    target = os.path.realpath(p)
    if target != root_real and not target.startswith(root_real + os.sep):
        res.add("error", "symlink-escape", "symlink points outside the skill folder", _rel(p, base))
    else:
        res.add("warning", "symlink", "symlink inside the skill; some installers do not copy symlinks", _rel(p, base))


def _check_file(path: Path, skill_dir: Path, base: Path, res: SkillResult, declared: set[str],
                disclosure_spans: dict[Path, list[tuple[int, int]]],
                undeclared: dict[str, tuple[str, int, int]]) -> None:
    rel = _rel(path, base)
    name = path.name
    ext = path.suffix.lower()

    if name in OS_JUNK_FILES:
        res.add("warning", "os-junk", "OS metadata file; delete it (it is gitignored, but local copies ship it)", rel)
        return
    if any(r.match(name) for r in TEST_FILE_RES):
        res.add("error", "test-file",
                "test files must not ship inside a skill folder (test runners in the user's project may execute them)",
                rel)
    if any(r.match(name) for r in SECRET_FILE_RES):
        res.add("error", "secret-file", "credential/config file must not ship inside a skill folder", rel)
    if ext in BINARY_EXTS:
        res.add("error", "binary", f"compiled/binary file ({ext}) is not allowed in a skill folder", rel)
        return

    try:
        size = path.stat().st_size
    except OSError:
        res.add("error", "unreadable", "file cannot be read", rel)
        return
    if size > LARGE_FILE_BYTES:
        res.add("warning", "large-file", f"file is {size / 1048576:.1f} MB (over 1 MB); keep skill files small", rel)

    with open(path, "rb") as fh:
        data = fh.read(MAX_SCAN_BYTES)

    if ext in MEDIA_MAGIC:
        if any(data.startswith(m) for m in MEDIA_MAGIC[ext]) and (ext != ".webp" or data[8:12] == b"WEBP"):
            return
        res.add("error", "disguised-binary", f"content does not match the {ext} file signature", rel)
        return
    if b"\x00" in data:
        res.add("error", "binary", "file contains NUL bytes (binary content is not allowed)", rel)
        return
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        res.add("warning", "not-utf8", "file is not valid UTF-8", rel)
        text = data.decode("latin-1")

    idx = _LineIndex(text)

    for m in HIDDEN_RE.finditer(text):
        cp = ord(m.group(0))
        if cp == 0xFEFF and m.start() == 0:
            continue
        line, col = idx.line_col(m.start())
        if cp in HIDDEN_ERROR or 0xE0000 <= cp <= 0xE007F:
            label = HIDDEN_ERROR.get(cp, "TAG CHARACTER")
            res.add("error", "hidden-unicode", f"hidden/bidi character U+{cp:04X} {label} at column {col}", rel, line)
        else:
            res.add("warning", "invisible-unicode", f"invisible character U+{cp:04X} {HIDDEN_WARN[cp]} at column {col}",
                    rel, line)

    for m in VS_RUN_RE.finditer(text):
        line, col = idx.line_col(m.start())
        res.add("error", "hidden-unicode",
                f"{len(m.group(0))} variation selector(s) at column {col} can hide a message", rel, line)

    # Join backslash-continued lines (same length, so offsets and line numbers stay valid).
    joined = text.replace("\\\r\n", "   ").replace("\\\n", "  ")
    for rx in PIPE_TO_SHELL_RES:
        for m in rx.finditer(joined):
            res.add("error", "pipe-to-shell", "downloads piped into a shell are not allowed (curl/wget ... | sh)",
                    rel, idx.line_col(m.start())[0])
    for start in _download_then_run(joined):
        res.add("error", "pipe-to-shell", "a downloaded file is executed (curl -o x.sh ... && bash x.sh)",
                rel, idx.line_col(start)[0])

    if ext == ".md":
        for m in DYNAMIC_SHELL_RE.finditer(text):
            res.add("error", "dynamic-shell",
                    f"dynamic shell injection {m.group(0).strip()[:40]!r} runs a command when the skill loads",
                    rel, idx.line_col(m.start())[0])

    for m in EXTRA_RUNNER_RE.finditer(text):
        runner = re.sub(r"[ \t]+", "-", m.group(1))
        spec = _extra_runner_spec(m.group(2))
        if spec and _is_pinned("uvx" if runner == "pipx-run" else "npx", spec) is False:
            res.add("warning", f"unpinned-{runner}", f"'{m.group(1)} {spec}' is not pinned to a version",
                    rel, idx.line_col(m.start())[0])

    for m in RUNNER_RE.finditer(text):
        cmd = m.group(1)
        for spec in _runner_specs(cmd, m.group(2)):
            pinned = _is_pinned(cmd, spec)
            if pinned is False:
                hint = "pkg@1.2.3" if cmd == "npx" else "pkg==1.2.3 or pkg@1.2.3"
                res.add("warning", f"unpinned-{cmd}", f"'{cmd} {spec}' is not pinned to a version (use {hint})",
                        rel, idx.line_col(m.start())[0])

    if name == "package.json":
        try:
            scripts = (json.loads(text) or {}).get("scripts") or {}
        except (ValueError, AttributeError):
            scripts = {}
        hooks = [k for k in INSTALL_HOOK_KEYS if isinstance(scripts, dict) and k in scripts]
        if hooks:
            res.add("error", "install-hook", f"package.json defines install hooks: {', '.join(hooks)}", rel)

    spans = disclosure_spans.get(path, [])
    for m in URL_RE.finditer(text):
        if any(s <= m.start() < e for s, e in spans):
            continue
        host = _host_of(m.group(0))
        if not host or _host_ignored(host) or _host_declared(host, declared):
            continue
        line = idx.line_col(m.start())[0]
        if host in undeclared:
            f, ln, count = undeclared[host]
            undeclared[host] = (f, ln, count + 1)
        else:
            undeclared[host] = (rel, line, 1)


# --- repo-level checks ------------------------------------------------------------------
def check_repo(root: Path, skill_names: list[str]) -> list[Issue]:
    issues: list[Issue] = []
    plugin_dir = root / ".claude-plugin"
    manifests: dict[str, Any] = {}
    for fname in ("plugin.json", "marketplace.json"):
        p = plugin_dir / fname
        if not p.is_file():
            continue
        try:
            manifests[fname] = json.loads(p.read_text("utf-8"))
        except ValueError as e:
            issues.append(Issue("error", "manifest-json", f"invalid JSON: {e}", _rel(p, root)))

    market = manifests.get("marketplace.json")
    if isinstance(market, dict):
        mrel = ".claude-plugin/marketplace.json"
        entries = [e for e in market.get("plugins") or [] if isinstance(e, dict) and e.get("source") in ("./", ".")]
        for entry in entries:
            listed = entry.get("skills")
            if not isinstance(listed, list):
                issues.append(Issue("warning", "marketplace-skills",
                                    f"plugin '{entry.get('name')}' has source './' but no explicit 'skills' list; "
                                    "Claude Code would then load every folder in skills/, including _template", mrel))
                continue
            listed_names = set()
            for s in listed:
                if not isinstance(s, str) or not s.startswith("./"):
                    issues.append(Issue("error", "marketplace-skills", f"skill path {s!r} must start with './'", mrel))
                    continue
                listed_names.add(Path(s).name)
                if Path(s).name == TEMPLATE_DIR:
                    issues.append(Issue("error", "marketplace-template", "skills/_template must not be listed", mrel))
                elif not (root / s).joinpath("SKILL.md").is_file():
                    issues.append(Issue("error", "marketplace-missing", f"listed skill {s!r} has no SKILL.md", mrel))
            for n in skill_names:
                if n not in listed_names:
                    issues.append(Issue("warning", "not-in-marketplace",
                                        f"skills/{n} is not listed in plugin '{entry.get('name')}' skills; "
                                        "Claude Code users will not get it", mrel))
        plugin = manifests.get("plugin.json")
        if isinstance(plugin, dict) and entries and plugin.get("name") != entries[0].get("name"):
            issues.append(Issue("warning", "plugin-name",
                                "plugin.json name differs from the marketplace entry name; keep them equal", mrel))

    issues += _plugin_code_issues(root, manifests)
    issues += _repo_hidden_unicode(root)

    readme = root / "README.md"
    if readme.is_file():
        text = readme.read_text("utf-8", errors="replace")
        m = re.search(r"<!--\s*skills:start\s*-->(.*?)<!--\s*skills:end\s*-->", text, re.S)
        if m:
            for n in skill_names:
                if not re.search(rf"(?<![\w-]){re.escape(n)}(?![\w-])", m.group(1)):
                    issues.append(Issue("warning", "not-in-readme", f"skills/{n} is missing from the README skills table",
                                        "README.md"))
    return issues


PLUGIN_CODE_PATHS = (
    ("hooks", "plugin hooks run shell commands for everyone who installs the plugin"),
    ("hooks.json", "plugin hooks run shell commands for everyone who installs the plugin"),
    (".mcp.json", "MCP servers start for everyone who installs the plugin"),
    (".lsp.json", "LSP servers start for everyone who installs the plugin"),
    ("bin", "plugin executables are added to every installer's PATH"),
    ("commands", "slash commands can run shell commands when invoked"),
    (".claude/settings.json", "project settings (hooks, permissions) apply to everyone who opens the repo"),
    (".claude/settings.local.json", "project settings (hooks, permissions) apply to everyone who opens the repo"),
)
PLUGIN_CODE_KEYS = ("hooks", "mcpServers", "lspServers", "commands")


def _plugin_code_issues(root: Path, manifests: dict[str, Any]) -> list[Issue]:
    """The hub ships skills only. Anything that executes code on install or session start is an
    error until a human reviews it and removes this check on purpose."""
    issues: list[Issue] = []
    for rel, why in PLUGIN_CODE_PATHS:
        if (root / rel).exists():
            issues.append(Issue("error", "plugin-code", f"{rel}: {why}; the hub ships skills only", rel))
    plugin = manifests.get("plugin.json")
    if isinstance(plugin, dict):
        for k in PLUGIN_CODE_KEYS:
            if k in plugin:
                issues.append(Issue("error", "plugin-code", f"plugin.json declares '{k}', which runs code on install",
                                    ".claude-plugin/plugin.json"))
    market = manifests.get("marketplace.json")
    if isinstance(market, dict):
        for entry in market.get("plugins") or []:
            if isinstance(entry, dict):
                for k in PLUGIN_CODE_KEYS:
                    if k in entry:
                        issues.append(Issue("error", "plugin-code",
                                            f"marketplace plugin '{entry.get('name')}' declares '{k}', which runs code",
                                            ".claude-plugin/marketplace.json"))
    return issues


REPO_SCAN_SKIP_DIRS = frozenset({".git", "node_modules", "skills", "runs", "__pycache__", ".venv"})


def _repo_hidden_unicode(root: Path) -> list[Issue]:
    """Hidden/bidi characters anywhere outside skills/ (skills are scanned per skill)."""
    issues: list[Issue] = []
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if d not in REPO_SCAN_SKIP_DIRS - {"skills"}
                             and not (here == root and d == "skills"))
        for fn in sorted(filenames):
            path = Path(dirpath) / fn
            if path.suffix.lower() in BINARY_EXTS or path.suffix.lower() in MEDIA_MAGIC or path.is_symlink():
                continue
            try:
                data = path.read_bytes()[:MAX_SCAN_BYTES]
            except OSError:
                continue
            if b"\x00" in data:
                continue
            text = data.decode("utf-8", errors="replace")
            idx = _LineIndex(text)
            for m in HIDDEN_RE.finditer(text):
                cp = ord(m.group(0))
                if cp in HIDDEN_ERROR or 0xE0000 <= cp <= 0xE007F:
                    line, col = idx.line_col(m.start())
                    issues.append(Issue("error", "hidden-unicode",
                                        f"hidden/bidi character U+{cp:04X} at column {col}", _rel(path, root), line))
            for m in VS_RUN_RE.finditer(text):
                line, col = idx.line_col(m.start())
                issues.append(Issue("error", "hidden-unicode",
                                    f"{len(m.group(0))} variation selector(s) at column {col} can hide a message",
                                    _rel(path, root), line))
    return issues


# --- discovery / CLI --------------------------------------------------------------------
def validate_paths(paths: list[Path], include_template: bool = False) -> Report:
    report = Report()
    for p in paths:
        p = Path(p)
        if not p.exists():
            raise FileNotFoundError(str(p))
        if p.is_dir() and (p / "SKILL.md").is_file():
            base = p.parent.parent if p.parent.name == "skills" else p.parent
            report.skills.append(validate_skill(p, base))
            continue
        repo_root = p if (p / "skills").is_dir() else None
        skills_dir = p / "skills" if repo_root else p
        if not skills_dir.is_dir():
            raise NotADirectoryError(str(p))
        base = repo_root if repo_root else skills_dir.parent
        names = []
        for child in sorted(skills_dir.iterdir(), key=lambda c: c.name):
            if not child.is_dir():
                continue
            if child.name.startswith("."):
                report.repo.append(Issue("warning", "hidden-dir",
                                         "hidden folder in skills/ is not validated, but some installers read it",
                                         _rel(child, base)))
                continue
            if child.name == TEMPLATE_DIR:
                if include_template:
                    report.skills.append(validate_skill(child, base, is_template=True))
                continue
            names.append(child.name)
            report.skills.append(validate_skill(child, base))
        if repo_root:
            report.repo.extend(check_repo(repo_root, names))
    return report


def _format_issue(i: Issue) -> str:
    loc = i.file + (f":{i.line}" if i.line else "")
    tag = "ERROR" if i.level == "error" else "WARN "
    return f"  {tag} [{i.code}] {loc}  {i.message}"


def format_text(report: Report, strict: bool = False) -> str:
    out = []
    for s in report.skills:
        status = "FAIL" if s.errors else "ok"
        extra = f" ({len(s.errors)} errors, {len(s.warnings)} warnings)" if s.issues else ""
        label = f"{s.path} [template]" if s.template else s.path
        out.append(f"{label}: {status}{extra}")
        out.extend(_format_issue(i) for i in s.issues)
    if report.repo:
        out.append("repository:")
        out.extend(_format_issue(i) for i in report.repo)
    verdict = "PASS" if report.ok(strict) else "FAIL"
    out.append(f"{verdict}: {len(report.skills)} skills, {report.error_count} errors, {report.warning_count} warnings"
               + (" (strict)" if strict else ""))
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Validate agent skill folders (Agent Skills spec + safety baseline).")
    ap.add_argument("paths", nargs="*", help="repo root, skills/ dir, or single skill dir (default: <repo>/skills)")
    ap.add_argument("--include-template", action="store_true", help="also validate skills/_template")
    ap.add_argument("--json", action="store_true", help="print a JSON report")
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors")
    args = ap.parse_args(argv)

    paths = [Path(p) for p in args.paths] or [Path(__file__).resolve().parent.parent]
    try:
        report = validate_paths(paths, include_template=args.include_template)
    except (FileNotFoundError, NotADirectoryError) as e:
        print(f"validate_skills: no skill folder or skills/ directory at {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report.to_dict(args.strict), indent=2, ensure_ascii=False))
    else:
        print(format_text(report, args.strict))
    return 0 if report.ok(args.strict) else 1


if __name__ == "__main__":
    sys.exit(main())
