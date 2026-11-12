"""
Log Handler — read sync log entries.

Actions:
  list          — Get recent log lines (default last 200)
  clear         — Clear the log file
  get_retention — Get current log retention setting
  set_retention — Set log retention (days) and trim old entries
  trim          — Delete log entries older than the configured retention
"""
import os
import re
import sys
import time
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import config_manager
import log_utils


def handle(params):
    action = params.getvalue("action", "list")

    if action == "list":
        return _list_logs(params)
    if action == "clear":
        return _clear_logs(params)
    if action == "get_level":
        return _get_level(params)
    if action == "set_level":
        return _set_level(params)
    if action == "get_retention":
        return _get_retention(params)
    if action == "set_retention":
        return _set_retention(params)
    if action == "trim":
        return _trim_logs(params)

    return {"success": False, "error": {"code": 101, "message": "Unknown action"}}


def _parse_log_lines(log_dir):
    """Read and parse all log files into structured records."""
    log_files = ["sync.log", "cron.log"]
    records = []

    for lf in log_files:
        path = os.path.join(log_dir, lf)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", errors="replace") as f:
                # Traceback frames and multi-line bodies stay with their
                # header line instead of showing up as separate entries.
                for _ts, block in log_utils.split_entries(f):
                    lines = [ln.rstrip() for ln in block if ln.strip()]
                    if not lines:
                        continue
                    line = lines[0].strip()
                    extra = lines[1:]

                    level = "info"
                    timestamp = ""
                    message = line

                    # Parse: "2026-04-11 19:50:40 [INFO] module: message"
                    m = re.match(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+\S+:\s*(.*)", line)
                    if m:
                        timestamp = m.group(1)
                        level = m.group(2).lower()
                        message = m.group(3)
                    else:
                        m2 = re.match(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(.*)", line)
                        if m2:
                            timestamp = m2.group(1)
                            message = m2.group(2)
                        text = "\n".join(lines).lower()
                        if "error" in text:
                            level = "error"
                        elif "warn" in text:
                            level = "warning"

                    if extra:
                        message = "\n".join([message] + extra)

                    records.append({
                        "level": level,
                        "timestamp": timestamp,
                        "message": log_utils.redact(message)
                    })
        except Exception:
            continue

    # Newest first
    records.reverse()
    return records


_LEVEL_RANK = {"debug": 0, "info": 1, "warning": 2, "error": 3}


def _list_logs(params):
    # Ext JS PagingToolbar sends "start" and "limit"
    try:
        offset = int(params.getvalue("start", "0"))
    except (ValueError, TypeError):
        offset = 0
    try:
        limit = min(int(params.getvalue("limit", "50")), 1000)
    except (ValueError, TypeError):
        limit = 50
    min_level = params.getvalue("level", "").strip().lower()

    log_dir = os.path.join(config_manager.PKG_VAR, "logs")
    all_records = _parse_log_lines(log_dir)

    if min_level in _LEVEL_RANK:
        threshold = _LEVEL_RANK[min_level]
        all_records = [
            r for r in all_records
            if _LEVEL_RANK.get(r.get("level", "info"), 1) >= threshold
        ]

    total = len(all_records)
    page = all_records[offset:offset + limit]

    return {
        "success": True,
        "total": total,
        "data": page
    }


def _clear_logs(params):
    log_dir = os.path.join(config_manager.PKG_VAR, "logs")
    for lf in ["sync.log", "cron.log"]:
        path = os.path.join(log_dir, lf)
        try:
            with open(path, "w") as f:
                f.write("")
        except Exception:
            pass

    return {"success": True, "data": {"message": "Logs cleared"}}


def _get_level(params):
    cfg = config_manager.load_config()
    return {"success": True, "data": {"level": cfg.get("log_level", "INFO")}}


def _set_level(params):
    level = params.getvalue("level", "").strip().upper()
    if level not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        return {"success": False, "error": {"code": 401, "message": "Invalid level"}}
    cfg = config_manager.load_config()
    cfg["log_level"] = level
    config_manager.save_config(cfg)
    return {"success": True, "data": {"level": level}}


_VALID_RETENTION_DAYS = (7, 14, 30, 90, 0)  # 0 = keep all


def _get_retention(params):
    cfg = config_manager.load_config()
    return {"success": True, "data": {"retention_days": cfg.get("log_retention_days", 7)}}


def _set_retention(params):
    try:
        days = int(params.getvalue("days", "7"))
    except (ValueError, TypeError):
        days = 30
    if days not in _VALID_RETENTION_DAYS:
        return {"success": False, "error": {"code": 402, "message": "Invalid retention value"}}
    cfg = config_manager.load_config()
    cfg["log_retention_days"] = days
    config_manager.save_config(cfg)
    if days > 0:
        _do_trim(days)
    return {"success": True, "data": {"retention_days": days}}


def _trim_logs(params):
    cfg = config_manager.load_config()
    days = cfg.get("log_retention_days", 30)
    if days <= 0:
        return {"success": True, "data": {"message": "Retention is unlimited, nothing trimmed", "removed": 0}}
    removed = _do_trim(days)
    return {"success": True, "data": {"message": "Trimmed entries older than %d days" % days, "removed": removed}}


def _do_trim(days):
    """Remove log lines older than `days` from all log files. Returns count of removed lines."""
    cutoff = datetime.now() - timedelta(days=days)
    cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")
    total_removed = 0

    for lf in log_utils.LOG_FILES:
        path = os.path.join(log_utils.LOG_DIR, lf)
        if not os.path.isfile(path):
            continue
        try:
            total_removed += log_utils.trim_file(path, cutoff_str)
        except Exception:
            pass

    return total_removed
