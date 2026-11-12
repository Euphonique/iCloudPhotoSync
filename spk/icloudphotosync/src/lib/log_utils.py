"""
Shared logging helpers: secret redaction and retention trimming.

Every log handler in the package uses RedactingFormatter, so auth tokens,
SRP proofs and 2FA codes never reach a log file — even at DEBUG level, where
pyicloud logs full request bodies.
"""
import logging
import os
import re

import config_manager

LOG_DIR = os.path.join(config_manager.PKG_VAR, "logs")

# All files the retention trim applies to.
LOG_FILES = ("sync.log", "cron.log", "album.log", "scheduler.log", "move.log")

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_TIMESTAMP_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})")

# JSON keys whose values are credentials or password-derived (SRP a/m1/m2).
_SECRET_JSON_KEYS = (
    "dsWebAuthToken", "trustToken", "trustTokens", "sessionToken",
    "session_token", "trust_token", "password", "securityCode",
    "a", "m1", "m2", "b", "salt", "scnt",
)
# "key": "value" | "key": [...] | "key": {...} — the closing delimiter is
# optional because error bodies are truncated to 1000 chars mid-value.
_SECRET_JSON_RE = re.compile(
    r'("(?:%s)"\s*:\s*)(\[[^\]]*\]?|\{[^}]*\}?|"[^"]*"?)'
    % "|".join(re.escape(k) for k in _SECRET_JSON_KEYS),
    re.IGNORECASE,
)
# key=value / key: value pairs (URL queries, headers, repr output).
_SECRET_KV_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|\w*token|cookie|authorization|x-apple-[\w-]*|"
    r"session[_-]?id|srp[_-]?[a-z]*|dsid)"
    r"\s*[:=]\s*['\"]?([^\s,&'\")}]+)",
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+\S+")


def redact(text):
    """Mask credentials in a log line (or a whole multi-line record)."""
    text = _SECRET_JSON_RE.sub(lambda m: m.group(1) + '"<redacted>"', text)
    text = _SECRET_KV_RE.sub(lambda m: "%s=<redacted>" % m.group(1), text)
    return _BEARER_RE.sub("Bearer <redacted>", text)


class RedactingFormatter(logging.Formatter):
    """Formatter that redacts the fully formatted record, traceback included."""

    def __init__(self, fmt=LOG_FORMAT, datefmt=DATE_FORMAT):
        super().__init__(fmt, datefmt)

    def format(self, record):
        return redact(super().format(record))


def configured_level():
    """Log level from the package config (default INFO)."""
    try:
        name = (config_manager.load_config() or {}).get("log_level", "INFO")
    except Exception:
        name = "INFO"
    return getattr(logging, str(name).upper(), logging.INFO)


def file_handler(filename):
    """FileHandler in LOG_DIR with the shared redacting formatter."""
    os.makedirs(LOG_DIR, exist_ok=True)
    handler = logging.FileHandler(os.path.join(LOG_DIR, filename))
    handler.setFormatter(RedactingFormatter())
    return handler


def split_entries(lines):
    """Group raw lines into log entries.

    Lines without a leading timestamp (traceback frames, multi-line Apple
    error bodies) belong to the preceding timestamped line. Lines before the
    first timestamp form an entry with timestamp None.
    Yields (timestamp_or_None, [lines]).
    """
    ts, block = None, []
    for line in lines:
        m = _TIMESTAMP_RE.match(line)
        if m:
            if block:
                yield ts, block
            ts, block = m.group(1), [line]
        else:
            block.append(line)
    if block:
        yield ts, block


def trim_file(path, cutoff_str):
    """Drop entries older than cutoff_str from path. Returns removed line count.

    Whole entries are removed, so traceback lines go together with their
    header. Lines without any timestamp at the head of the file are leftovers
    of entries whose header an older trim already removed; they go too.
    The file is rewritten in place: long-running processes keep their
    O_APPEND handle on it, so os.replace() would make them write into an
    unlinked inode.
    """
    with open(path, "r+", errors="replace") as f:
        lines = f.readlines()
        kept = []
        for ts, block in split_entries(lines):
            if ts is not None and ts >= cutoff_str:
                kept.extend(block)
        removed = len(lines) - len(kept)
        if removed:
            f.seek(0)
            f.writelines(kept)
            f.truncate()
    return removed
