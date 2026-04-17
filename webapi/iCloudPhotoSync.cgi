#!/usr/bin/env python3
import json
import os
import sys
import cgi

# Add our library path
PKG_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(PKG_DIR, "lib"))

from handlers import status as status_handler
from handlers import auth as auth_handler
from handlers import account as account_handler
from handlers import album as album_handler
from handlers import sync as sync_handler
from handlers import config as config_handler
from handlers import log as log_handler
from handlers import move as move_handler

HANDLERS = {
    "status": status_handler.handle,
    "auth": auth_handler.handle,
    "account": account_handler.handle,
    "album": album_handler.handle,
    "sync": sync_handler.handle,
    "config": config_handler.handle,
    "log": log_handler.handle,
    "move": move_handler.handle,
}


def respond(success, data=None, error=None):
    print("Content-Type: application/json")
    print()
    resp = {"success": success}
    if data is not None:
        resp["data"] = data
    if error is not None:
        resp["error"] = error
    print(json.dumps(resp))


def main():
    params = cgi.FieldStorage()
    method = params.getvalue("method", "")
    handler = HANDLERS.get(method)

    if not handler:
        respond(False, error={"code": 100, "message": "Unknown method: %s" % method})
        return

    try:
        result = handler(params)
        respond(**result)
    except Exception as e:
        import logging
        logging.getLogger("webapi.cgi").exception("Handler error")
        respond(False, error={"code": 500, "message": "Internal server error"})


if __name__ == "__main__":
    main()
