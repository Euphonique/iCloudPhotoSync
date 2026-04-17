import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
import config_manager


def handle(params):
    action = params.getvalue("action", "get")

    if action == "get":
        accounts = config_manager.get_accounts()
        return {
            "success": True,
            "data": {
                "running": True,
                "sync_status": "idle",
                "accounts": len(accounts),
                "next_sync": None,
                "version": "1.0.0",
                "timestamp": int(time.time()),
            },
        }

    return {"success": False, "error": {"code": 101, "message": "Unknown action"}}
