#!/usr/bin/env python3
"""
Move Runner — background process that relocates synced photos after a
target_dir change.

Usage: python3 move_runner.py <account_id> <old_dir_b64> <new_dir_b64>
  old_dir and new_dir are base64-encoded to sidestep quoting issues with
  paths containing spaces or special characters.
"""
import base64
import logging
import os
import sys

PKG_TARGET = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LIB_DIR = os.path.join(PKG_TARGET, "lib")
VENDOR_DIR = os.path.join(LIB_DIR, "vendor")
sys.path.insert(0, LIB_DIR)
if os.path.isdir(VENDOR_DIR):
    sys.path.insert(0, VENDOR_DIR)

import log_utils
import move_engine

logging.basicConfig(
    handlers=[log_utils.file_handler("move.log")],
    level=log_utils.configured_level(),
)
LOGGER = logging.getLogger("move_runner")


def main():
    if len(sys.argv) < 4:
        LOGGER.error("Usage: move_runner.py <account_id> <old_b64> <new_b64>")
        sys.exit(1)
    account_id = sys.argv[1]
    try:
        old_dir = base64.b64decode(sys.argv[2]).decode("utf-8")
        new_dir = base64.b64decode(sys.argv[3]).decode("utf-8")
    except Exception:
        LOGGER.exception("Failed to decode arguments")
        sys.exit(2)

    LOGGER.info("Move start: account=%s old=%s new=%s", account_id, old_dir, new_dir)
    try:
        p = move_engine.run_move(account_id, old_dir, new_dir)
        LOGGER.info("Move finished: status=%s moved=%d failed=%d",
                    p.status, p.moved_files, p.failed_files)
    except Exception:
        LOGGER.exception("Move crashed")


if __name__ == "__main__":
    main()
