#!/usr/bin/env python3
"""itscrub - find and mask Italian personal data in logs, text and source code.

Detects codice fiscale, partita IVA, Italian IBAN, e-mail and PEC addresses,
phone numbers, licence plates and tessera sanitaria numbers. Identifiers that
carry a check digit (codice fiscale, partita IVA, IBAN) are verified, which
keeps false positives low enough to run the scanner as a pre-commit hook.

    itscrub scan [PATH ...]      report findings, exit 1 if any (pre-commit / CI)
    itscrub mask [FILE ...]      copy input to output with personal data masked
    itscrub kinds                list the detectors

As a library:

    from itscrub import scrub, find, ScrubFilter
    clean = scrub("CF RSSMRA80A01H501U")        # 'CF [CODICE_FISCALE]'
    logging.getLogger().addFilter(ScrubFilter())

Standard library only. Nothing is sent anywhere: all processing is local.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import hmac
import json
import logging
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

__version__ = "0.1.0"
__all__ = ["find", "scrub", "Finding", "Allowlist", "ScrubFilter",
           "cf_is_valid", "piva_is_valid", "iban_is_valid",
           "LOW", "MEDIUM", "HIGH", "KINDS"]

log = logging.getLogger("itscrub")

LOW, MEDIUM, HIGH = 1, 2, 3
CONFIDENCE = {"low": LOW, "medium": MEDIUM, "high": HIGH}
CONFIDENCE_NAME = {v: k for k, v in CONFIDENCE.items()}

KINDS = ("codice_fiscale", "partita_iva", "iban", "pec", "email",
         "telefono", "targa", "tessera_sanitaria")

SALT_ENV = "ITSCRUB_SALT"
IGNORE_MARK = re.compile(r"itscrub:\s*ignore")

# ---------------------------------------------------------------------------
# check digits
# ---------------------------------------------------------------------------

_CF_ODD = dict(zip("0123456789", (1, 0, 5, 7, 9, 13, 15, 17, 19, 21)))
_CF_ODD.update(zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                   (1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3,
                    6, 8, 12, 14, 16, 10, 22, 25, 24, 23)))


def cf_is_valid(value: str) -> bool:
    """True if `value` is a 16-character codice fiscale with a correct check letter."""
    cf = value.upper()
    if len(cf) != 16 or not cf.isalnum() or not cf.isascii():
        return False
    total = 0
    for i, ch in enumerate(cf[:15]):
        if i % 2 == 0:                      # 1st, 3rd, ... character
            total += _CF_ODD[ch]
        else:
            total += int(ch) if ch.isdigit() else ord(ch) - 65
    return chr(65 + total % 26) == cf[15]


def piva_is_valid(value: str) -> bool:
    """True if `value` is an 11-digit partita IVA with a correct check digit."""
    if len(value) != 11 or not value.isdigit() or not value.isascii():
        return False
    if value == "0" * 11:
        return False
    total = 0
    for i, ch in enumerate(value[:10]):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - total % 10) % 10 == int(value[10])


def iban_is_valid(value: str) -> bool:
    """True if `value` is an Italian IBAN (27 characters) passing the mod-97 check."""
    iban = re.sub(r"\s", "", value).upper()
    if len(iban) != 27 or not iban.startswith("IT") or not iban.isalnum() or not iban.isascii():
        return False
    moved = iban[4:] + iban[:4]
    digits = "".join(str(int(c, 36)) for c in moved)
    return int(digits) % 97 == 1


# ---------------------------------------------------------------------------
# detectors
# ---------------------------------------------------------------------------

_B = r"(?<![A-Za-z0-9])"
_E = r"(?![A-Za-z0-9])"

_CTX_PIVA = re.compile(r"p\.?\s?iva|partita[\s_]+iva|vat|c\.?\s?f\.?\b|codice[\s_]+fiscale")
_CTX_PHONE = re.compile(r"tel|cell|mobile|phone|fax|whatsapp|chiama|numero")
_CTX_PLATE = re.compile(r"targa|targat|plate|veicolo|vehicle")
_CTX_TS = re.compile(r"tessera|sanitaria|\bteam\b|health\s*card")

_PEC_LABELS = {"legalmail", "postecert", "postacert", "cert", "sicurezzapostale",
               "pecimprese", "casellapec", "actaliscertymail"}
# things like "logo@2x.png" look like an address but are file names
_ASSET_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "css", "js",
               "json", "html", "map"}


def _ctx(pattern: "re.Pattern[str]", line: str, start: int) -> bool:
    return bool(pattern.search(line[max(0, start - 40):start].lower()))


Result = Optional[Tuple[str, int]]


def _h_cf(m: "re.Match[str]", line: str) -> Result:
    v = m.group(0)
    if not any(c.isdigit() for c in v):
        return None                          # a 16-letter word, not a code
    return ("codice_fiscale", HIGH if cf_is_valid(v) else LOW)


def _h_piva(m: "re.Match[str]", line: str) -> Result:
    v = m.group(0)
    prefixed = v.startswith("IT")
    if not piva_is_valid(v[2:] if prefixed else v):
        return None
    strong = prefixed or _ctx(_CTX_PIVA, line, m.start())
    return ("partita_iva", HIGH if strong else MEDIUM)


def _h_iban(m: "re.Match[str]", line: str) -> Result:
    return ("iban", HIGH if iban_is_valid(m.group(0)) else LOW)


def _h_email(m: "re.Match[str]", line: str) -> Result:
    domain = m.group(0).rsplit("@", 1)[1].lower()
    labels = domain.split(".")
    if labels[-1] in _ASSET_TLDS:
        return None
    is_pec = any(l == "pec" or l.startswith("pec") or l.endswith("pec") or l in _PEC_LABELS
                 for l in labels[:-1])
    return ("pec" if is_pec else "email", MEDIUM)


def _h_mobile(m: "re.Match[str]", line: str) -> Result:
    if m.group("pfx") or _ctx(_CTX_PHONE, line, m.start()):
        return ("telefono", HIGH)
    if re.search(r"[\s.\-/]", m.group(0)):
        return ("telefono", MEDIUM)
    return ("telefono", LOW)                 # ten bare digits: could be any number


def _h_landline_prefixed(m: "re.Match[str]", line: str) -> Result:
    return ("telefono", HIGH)


def _h_landline_bare(m: "re.Match[str]", line: str) -> Result:
    # a bare number starting with 0 means nothing without a hint next to it
    return ("telefono", MEDIUM) if _ctx(_CTX_PHONE, line, m.start()) else None


def _h_plate(m: "re.Match[str]", line: str) -> Result:
    return ("targa", HIGH if _ctx(_CTX_PLATE, line, m.start()) else LOW)


def _h_ts(m: "re.Match[str]", line: str) -> Result:
    return ("tessera_sanitaria", HIGH if _ctx(_CTX_TS, line, m.start()) else MEDIUM)


@dataclass(frozen=True)
class _Detector:
    kinds: Tuple[str, ...]
    priority: int
    regex: "re.Pattern[str]"
    handler: Callable[["re.Match[str]", str], Result]


_DETECTORS: Tuple[_Detector, ...] = (
    _Detector(("iban",), 90, re.compile(
        _B + r"IT[0-9]{2} ?[A-Z][0-9]{3} ?[0-9]{4} ?[0-9]{3}[0-9A-Z] ?[0-9A-Z]{4} ?"
             r"[0-9A-Z]{4} ?[0-9A-Z]{3}" + _E, re.I), _h_iban),
    _Detector(("codice_fiscale",), 80, re.compile(
        _B + r"[A-Z]{6}[0-9LMNPQRSTUV]{2}[ABCDEHLMPRST][0-9LMNPQRSTUV]{2}[A-Z]"
             r"[0-9LMNPQRSTUV]{3}[A-Z]" + _E, re.I), _h_cf),
    _Detector(("tessera_sanitaria",), 70, re.compile(_B + r"80380[0-9]{15}" + _E), _h_ts),
    _Detector(("partita_iva",), 60, re.compile(_B + r"(?:IT)?[0-9]{11}" + _E), _h_piva),
    _Detector(("email", "pec"), 50, re.compile(
        r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,24}"
        r"(?![A-Za-z0-9\-])"), _h_email),
    _Detector(("telefono",), 40, re.compile(
        r"(?<![\w+])(?<![0-9][.,])(?P<pfx>(?:\+|00)39[\s.\-]?)?"
        r"3[0-9]{2}[\s.\-/]?[0-9]{3}[\s.\-]?[0-9]{3,4}(?!\w)"), _h_mobile),
    _Detector(("telefono",), 39, re.compile(
        r"(?<![\w+])(?:\+|00)39[\s.\-]?0[0-9]{1,3}[\s.\-/]?[0-9]{4,8}(?!\w)"),
        _h_landline_prefixed),
    _Detector(("telefono",), 20, re.compile(
        r"(?<![\w+])(?<![0-9][.,])0[0-9]{1,3}[\s.\-/]?[0-9]{5,8}(?!\w)"), _h_landline_bare),
    _Detector(("targa",), 10, re.compile(
        _B + r"[A-HJ-NPR-TV-Z]{2} ?[0-9]{3} ?[A-HJ-NPR-TV-Z]{2}" + _E), _h_plate),
)

# ---------------------------------------------------------------------------
# allowlist
# ---------------------------------------------------------------------------

_DEFAULT_ALLOW = (
    r"(?i)^[^@]+@(?:[a-z0-9\-]+\.)*example\.(?:com|org|net|it)$",
    r"(?i)^[^@]+@[^@]+\.(?:test|invalid|localhost|local)$",
    r"(?i)^(?:noreply|no-reply|donotreply|git|hg)@",
    r"(?i)@users\.noreply\.github\.com$",
)


def _normalise(value: str) -> str:
    return re.sub(r"[\s.\-/]", "", value).upper()


class Allowlist:
    """Values that must never be reported or masked.

    Entries are literal values (compared ignoring case, spaces and separators)
    or regular expressions written as ``re:<pattern>`` and searched in the value.
    """

    def __init__(self, entries: Iterable[str] = (), defaults: bool = True) -> None:
        self._literals: Set[str] = set()
        self._patterns: List["re.Pattern[str]"] = []
        if defaults:
            self._patterns.extend(re.compile(p) for p in _DEFAULT_ALLOW)
        for raw in entries:
            entry = raw.strip()
            if not entry or entry.startswith("#"):
                continue
            if entry.startswith("re:"):
                self._patterns.append(re.compile(entry[3:]))
            else:
                self._literals.add(_normalise(entry))

    @classmethod
    def from_file(cls, path: str, defaults: bool = True) -> "Allowlist":
        with open(path, encoding="utf-8") as fh:
            return cls(fh.read().splitlines(), defaults=defaults)

    def allows(self, value: str) -> bool:
        if _normalise(value) in self._literals:
            return True
        return any(p.search(value) for p in self._patterns)


_DEFAULT_ALLOWLIST = Allowlist()

# ---------------------------------------------------------------------------
# core
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    kind: str
    value: str
    confidence: int
    line: int        # 1-based
    col: int         # 1-based
    start: int       # offset in the text passed to find()
    end: int

    @property
    def confidence_name(self) -> str:
        return CONFIDENCE_NAME[self.confidence]


def _check_kinds(kinds: Optional[Iterable[str]]) -> Optional[Set[str]]:
    if kinds is None:
        return None
    wanted = set(kinds)
    unknown = wanted - set(KINDS)
    if unknown:
        raise ValueError("unknown kind(s): %s (known: %s)"
                         % (", ".join(sorted(unknown)), ", ".join(KINDS)))
    return wanted


def _find_in_line(line: str, min_confidence: int, kinds: Optional[Set[str]],
                  allow: Optional[Allowlist]) -> List[Tuple[int, int, str, int]]:
    """Non-overlapping (start, end, kind, confidence) in one line, left to right."""
    cands = []
    for det in _DETECTORS:
        if kinds is not None and not kinds.intersection(det.kinds):
            continue
        for m in det.regex.finditer(line):
            res = det.handler(m, line)
            if res is None:
                continue
            kind, conf = res
            if conf < min_confidence or (kinds is not None and kind not in kinds):
                continue
            if allow is not None and allow.allows(m.group(0)):
                continue
            cands.append((conf, det.priority, m.start(), m.end(), kind))
    cands.sort(key=lambda c: (-c[0], -c[1], c[2]))
    taken: List[Tuple[int, int, str, int]] = []
    for conf, _prio, start, end, kind in cands:
        if all(end <= t[0] or start >= t[1] for t in taken):
            taken.append((start, end, kind, conf))
    taken.sort()
    return taken


def find(text: str, min_confidence: int = MEDIUM, kinds: Optional[Iterable[str]] = None,
         allow: Optional[Allowlist] = _DEFAULT_ALLOWLIST) -> List[Finding]:
    """Return the personal data found in `text`, in order of appearance."""
    wanted = _check_kinds(kinds)
    out: List[Finding] = []
    offset = 0
    for n, line in enumerate(text.splitlines(keepends=True), 1):
        for start, end, kind, conf in _find_in_line(line, min_confidence, wanted, allow):
            out.append(Finding(kind, line[start:end], conf, n, start + 1,
                               offset + start, offset + end))
        offset += len(line)
    return out


def _partial(kind: str, value: str) -> str:
    if kind in ("email", "pec"):
        local, _, domain = value.partition("@")
        return local[:1] + "***@" + domain
    if len(value) <= 6:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def _replacement(kind: str, value: str, style: str, salt: Optional[bytes]) -> str:
    label = kind.upper()
    if style == "placeholder":
        return "[%s]" % label
    if style == "partial":
        return _partial(kind, value)
    if style == "hash":
        if not salt:
            raise ValueError("style 'hash' needs a secret salt (set %s)" % SALT_ENV)
        digest = hmac.new(salt, _normalise(value).encode("utf-8"), hashlib.sha256).hexdigest()
        return "[%s:%s]" % (label, digest[:12])
    raise ValueError("unknown style: %s" % style)


def _salt_bytes(salt: "Optional[str | bytes]") -> Optional[bytes]:
    if salt is None:
        salt = os.environ.get(SALT_ENV) or None
    if isinstance(salt, str):
        return salt.encode("utf-8")
    return salt


def scrub(text: str, style: str = "placeholder", min_confidence: int = LOW,
          kinds: Optional[Iterable[str]] = None, salt: "Optional[str | bytes]" = None,
          allow: Optional[Allowlist] = _DEFAULT_ALLOWLIST) -> str:
    """Return `text` with personal data replaced.

    style: 'placeholder' -> [CODICE_FISCALE]; 'partial' -> RS************1U;
    'hash' -> [CODICE_FISCALE:3f9a...] (keyed HMAC, same value gives same token).
    """
    wanted = _check_kinds(kinds)
    key = _salt_bytes(salt) if style == "hash" else None
    if style == "hash" and not key:
        raise ValueError("style 'hash' needs a secret salt (set %s)" % SALT_ENV)
    if style not in ("placeholder", "partial", "hash"):
        raise ValueError("unknown style: %s" % style)
    out = []
    for line in text.splitlines(keepends=True):
        pos = 0
        for start, end, kind, _conf in _find_in_line(line, min_confidence, wanted, allow):
            out.append(line[pos:start])
            out.append(_replacement(kind, line[start:end], style, key))
            pos = end
        out.append(line[pos:])
    return "".join(out)


class ScrubFilter(logging.Filter):
    """logging filter that masks personal data in the formatted message.

    Attach it to a handler (or logger): the message and its arguments are
    merged and scrubbed before any formatter sees them.
    """

    def __init__(self, style: str = "placeholder", min_confidence: int = LOW,
                 kinds: Optional[Iterable[str]] = None, salt: "Optional[str | bytes]" = None,
                 allow: Optional[Allowlist] = _DEFAULT_ALLOWLIST) -> None:
        super().__init__()
        self._kw = dict(style=style, min_confidence=min_confidence, kinds=kinds,
                        salt=salt, allow=allow)
        scrub("", **self._kw)                # fail at set-up time, not at log time

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:                    # bad format string: leave it to logging
            return True
        record.msg = scrub(message, **self._kw)
        record.args = None
        return True


# ---------------------------------------------------------------------------
# files
# ---------------------------------------------------------------------------

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
             ".mypy_cache", ".pytest_cache", ".tox", "dist", "build", ".idea", ".next"}
DEFAULT_MAX_SIZE = 5 * 1024 * 1024


def _excluded(path: str, patterns: Sequence[str]) -> bool:
    norm = path.replace(os.sep, "/")
    base = os.path.basename(norm)
    return any(fnmatch.fnmatch(norm, p) or fnmatch.fnmatch(base, p) for p in patterns)


def iter_files(paths: Sequence[str], exclude: Sequence[str] = ()) -> Iterator[str]:
    for path in paths:
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS
                                 and not _excluded(os.path.join(root, d), exclude))
                for name in sorted(files):
                    full = os.path.normpath(os.path.join(root, name))
                    if not _excluded(full, exclude):
                        yield full
        elif not _excluded(path, exclude):
            yield path


def _read_text(path: str, max_size: int) -> Optional[str]:
    """File content, or None if it should be skipped (binary / too large)."""
    if os.path.getsize(path) > max_size:
        log.info("skipped (larger than %d bytes): %s", max_size, path)
        return None
    with open(path, "rb") as fh:
        data = fh.read()
    if b"\x00" in data[:8192]:
        log.debug("skipped (binary): %s", path)
        return None
    return data.decode("utf-8", "replace")


def scan_text(text: str, min_confidence: int, kinds: Optional[Iterable[str]],
              allow: Optional[Allowlist]) -> List[Finding]:
    """find(), minus the lines carrying an `itscrub: ignore` marker."""
    ignored = {n for n, line in enumerate(text.splitlines(), 1) if IGNORE_MARK.search(line)}
    return [f for f in find(text, min_confidence, kinds, allow) if f.line not in ignored]


# ---------------------------------------------------------------------------
# command line
# ---------------------------------------------------------------------------

def _load_allow(args: argparse.Namespace) -> Allowlist:
    defaults = not args.no_default_allow
    path = args.allow
    if path is None and os.path.isfile(".itscrub-allow"):
        path = ".itscrub-allow"
    if path:
        return Allowlist.from_file(path, defaults=defaults)
    return Allowlist(defaults=defaults)


def _kinds_arg(value: Optional[str]) -> Optional[Set[str]]:
    if not value:
        return None
    return _check_kinds(k.strip() for k in value.split(",") if k.strip())


def _gh_escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def cmd_scan(args: argparse.Namespace) -> int:
    allow = _load_allow(args)
    kinds = _kinds_arg(args.kinds)
    min_conf = CONFIDENCE[args.min_confidence]
    results: List[Tuple[str, Finding]] = []
    scanned = errors = 0

    sources: List[Tuple[str, Optional[str]]] = []
    paths = args.paths or ["."]
    if "-" in paths:
        sources.append(("<stdin>", sys.stdin.read()))
        paths = [p for p in paths if p != "-"]
    for path in iter_files(paths, args.exclude):
        sources.append((path, None))

    for name, text in sources:
        if text is None:
            try:
                text = _read_text(name, args.max_size)
            except OSError as exc:
                log.error("cannot read %s: %s", name, exc.strerror or exc)
                errors += 1
                continue
            if text is None:
                continue
        scanned += 1
        results.extend((name, f) for f in scan_text(text, min_conf, kinds, allow))

    def shown(f: Finding) -> str:
        return f.value if args.show_values else _partial(f.kind, f.value)

    if args.format == "json":
        json.dump([{"path": p, "line": f.line, "col": f.col, "kind": f.kind,
                    "confidence": f.confidence_name, "value": shown(f)}
                   for p, f in results], sys.stdout, indent=1, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        for p, f in results:
            if args.format == "github":
                print("::warning file=%s,line=%d,col=%d,title=itscrub %s::%s"
                      % (_gh_escape(p), f.line, f.col, f.kind,
                         _gh_escape("possible %s (%s confidence): %s"
                                    % (f.kind.replace("_", " "), f.confidence_name, shown(f)))))
            else:
                print("%s:%d:%d: %s (%s) %s"
                      % (p, f.line, f.col, f.kind, f.confidence_name, shown(f)))

    files_hit = len({p for p, _ in results})
    print("itscrub: %d finding(s) in %d file(s), %d scanned"
          % (len(results), files_hit, scanned), file=sys.stderr)
    if errors:
        return 2
    return 1 if results else 0


def _mask_stream(src: Iterable[str], dst, args: argparse.Namespace,
                 allow: Allowlist, kinds: Optional[Set[str]], salt: Optional[bytes]) -> None:
    min_conf = CONFIDENCE[args.min_confidence]
    for line in src:
        dst.write(scrub(line, args.style, min_conf, kinds, salt, allow))
        dst.flush()                          # keeps `tail -f log | itscrub mask` live


def cmd_mask(args: argparse.Namespace) -> int:
    allow = _load_allow(args)
    kinds = _kinds_arg(args.kinds)
    salt = _salt_bytes(None)
    if args.style == "hash" and not salt:
        log.error("style 'hash' needs a secret salt in the %s environment variable", SALT_ENV)
        return 2
    if args.in_place and not args.files:
        log.error("--in-place needs at least one file")
        return 2
    if args.in_place and args.output:
        log.error("--in-place and --output cannot be used together")
        return 2

    if args.in_place:
        for path in args.files:
            folder = os.path.dirname(os.path.abspath(path))
            with open(path, encoding="utf-8", errors="replace", newline="") as src, \
                    tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="", dir=folder,
                                                delete=False, suffix=".itscrub") as tmp:
                try:
                    _mask_stream(src, tmp, args, allow, kinds, salt)
                except BaseException:
                    tmp.close()
                    os.unlink(tmp.name)
                    raise
            os.replace(tmp.name, path)
        return 0

    out = open(args.output, "w", encoding="utf-8", newline="") if args.output else sys.stdout
    try:
        if not args.files or args.files == ["-"]:
            _mask_stream(sys.stdin, out, args, allow, kinds, salt)
        else:
            for path in args.files:
                with open(path, encoding="utf-8", errors="replace", newline="") as src:
                    _mask_stream(src, out, args, allow, kinds, salt)
    finally:
        if args.output:
            out.close()
    return 0


_KIND_HELP = {
    "codice_fiscale": "personal tax code, 16 characters, check letter verified",
    "partita_iva": "VAT number, 11 digits (optional IT prefix), check digit verified",
    "iban": "Italian IBAN, 27 characters, mod-97 verified",
    "pec": "certified e-mail address (recognised by provider domain)",
    "email": "e-mail address",
    "telefono": "mobile and landline numbers, with or without +39",
    "targa": "vehicle licence plate, current AA 000 AA format",
    "tessera_sanitaria": "health card number, 20 digits starting with 80380",
}


def cmd_kinds(args: argparse.Namespace) -> int:
    for kind in KINDS:
        print("%-18s %s" % (kind, _KIND_HELP[kind]))
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="itscrub", description="Find and mask Italian personal data.")
    ap.add_argument("--version", action="version", version="itscrub " + __version__)
    ap.add_argument("-v", "--verbose", action="count", default=0,
                    help="more diagnostics on stderr (never prints the values found)")
    sub = ap.add_subparsers(dest="command")

    def common(p: argparse.ArgumentParser, default_conf: str) -> None:
        p.add_argument("--min-confidence", choices=list(CONFIDENCE), default=default_conf,
                       help="lowest confidence to act on (default: %(default)s)")
        p.add_argument("--kinds", metavar="K1,K2",
                       help="only these detectors (see `itscrub kinds`)")
        p.add_argument("--allow", metavar="FILE",
                       help="allowlist file (default: ./.itscrub-allow if present)")
        p.add_argument("--no-default-allow", action="store_true",
                       help="also act on example.com, noreply@ and similar addresses")

    s = sub.add_parser("scan", help="report findings; exit status 1 if any")
    s.add_argument("paths", nargs="*", help="files or directories ('-' = stdin, default: .)")
    common(s, "medium")
    s.add_argument("--format", choices=("text", "json", "github"), default="text")
    s.add_argument("--show-values", action="store_true",
                   help="print the values in full instead of partially masked")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="skip paths matching this pattern (repeatable)")
    s.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE, metavar="BYTES",
                   help="skip larger files (default: %(default)s)")
    s.set_defaults(func=cmd_scan)

    m = sub.add_parser("mask", help="copy input to output with personal data masked")
    m.add_argument("files", nargs="*", help="input files (default: stdin)")
    common(m, "low")
    m.add_argument("--style", choices=("placeholder", "partial", "hash"), default="placeholder")
    m.add_argument("-o", "--output", metavar="FILE", help="write here instead of stdout")
    m.add_argument("--in-place", action="store_true", help="rewrite the input files")
    m.set_defaults(func=cmd_mask)

    k = sub.add_parser("kinds", help="list the detectors")
    k.set_defaults(func=cmd_kinds)
    return ap


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    logging.basicConfig(
        stream=sys.stderr, format="itscrub: %(levelname)s: %(message)s", force=True,
        level=logging.WARNING - 10 * min(args.verbose, 2))
    if not args.command:
        ap.print_help()
        return 2
    try:
        return args.func(args)
    except (ValueError, re.error) as exc:
        log.error("%s", exc)
        return 2
    except OSError as exc:
        log.error("%s", exc)
        return 2
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
