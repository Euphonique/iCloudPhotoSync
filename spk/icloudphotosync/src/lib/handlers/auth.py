"""
Auth Handler — Apple ID login and 2FA verification.

Actions:
  login       — Start login with apple_id + password, returns 2FA status
  verify_2fa  — Submit 6-digit 2FA code
  status      — Check if session for account_id is still authenticated
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import time

import config_manager
import icloud_client
import notifier


def handle(params):
    action = params.getvalue("action", "")

    if action == "login":
        return _login(params)
    if action == "verify_2fa":
        return _verify_2fa(params)
    if action == "send_sms":
        return _send_sms(params)
    if action == "status":
        return _auth_status(params)

    return {"success": False, "error": {"code": 101, "message": "Unknown action"}}


def _login(params):
    apple_id = params.getvalue("apple_id", "").strip()
    password = params.getvalue("password", "").strip()

    if not apple_id or not password:
        return {
            "success": False,
            "error": {"code": 201, "message": "apple_id and password required"}
        }

    # Find existing account by apple_id; only create after credentials validate
    account = None
    for acc in config_manager.get_accounts():
        if acc["apple_id"] == apple_id:
            account = acc
            break

    created_new = False
    if not account:
        account = config_manager.add_account(apple_id)
        created_new = True

    # Clear any cached client so we get a fresh one with the password
    icloud_client.remove_client(account["id"])

    # Attempt login
    client = icloud_client.get_client(account["id"], apple_id, password)
    result = client.login()

    if not result["success"]:
        if created_new:
            icloud_client.remove_client(account["id"])
            config_manager.remove_account(account["id"])
        return {
            "success": False,
            "error": {"code": 202, "message": result.get("error", "Login failed")}
        }

    if result.get("requires_2fa"):
        config_manager.update_account(account["id"], {"status": "pending_2fa"})
        # Store password temporarily so SMS re-login works in a later CGI request
        config_manager.save_pending_password(account["id"], password)
        data = {
            "account_id": account["id"],
            "requires_2fa": True,
            "message": result.get("message", "2FA required"),
        }
        return {"success": True, "data": data}

    # Login succeeded without 2FA
    config_manager.update_account(account["id"], {
        "status": "authenticated",
        "authenticated_at": int(time.time()),
    })
    config_manager.clear_pending_password(account["id"])
    notifier.clear_all_markers(account["id"])
    return {
        "success": True,
        "data": {
            "account_id": account["id"],
            "requires_2fa": False,
            "message": "Login successful"
        }
    }


def _send_sms(params):
    account_id = params.getvalue("account_id", "").strip()

    if not account_id:
        return {
            "success": False,
            "error": {"code": 203, "message": "account_id required"}
        }

    account = config_manager.get_account(account_id)
    if not account:
        return {
            "success": False,
            "error": {"code": 204, "message": "Account not found"}
        }

    # Retrieve stored password — SMS needs a fresh re-login
    password = config_manager.get_pending_password(account_id)
    if not password:
        return {
            "success": False,
            "error": {"code": 207, "message": "Password not available, please login again"}
        }

    client = icloud_client.get_client(account_id, account["apple_id"], password)
    result = client.send_sms_code()

    if not result["success"]:
        return {
            "success": False,
            "error": {"code": 206, "message": result.get("error", "SMS send failed")}
        }

    return {
        "success": True,
        "data": {
            "message": result.get("message", "SMS sent"),
            "phone_id": result.get("phone_id"),
            "phone_number": result.get("phone_number"),
        }
    }


def _verify_2fa(params):
    account_id = params.getvalue("account_id", "").strip()
    code = params.getvalue("code", "").strip()

    if not account_id or not code:
        return {
            "success": False,
            "error": {"code": 203, "message": "account_id and code required"}
        }

    account = config_manager.get_account(account_id)
    if not account:
        return {
            "success": False,
            "error": {"code": 204, "message": "Account not found"}
        }

    phone_id = params.getvalue("phone_id", "").strip() or None
    password = config_manager.get_pending_password(account_id)
    client = icloud_client.get_client(account_id, account["apple_id"], password)
    result = client.verify_2fa(code, phone_id=phone_id)

    if not result["success"]:
        return {
            "success": False,
            "error": {"code": 205, "message": result.get("error", "2FA failed")}
        }

    config_manager.update_account(account_id, {
        "status": "authenticated",
        "authenticated_at": int(time.time()),
    })
    config_manager.clear_pending_password(account_id)
    notifier.clear_all_markers(account_id)
    return {
        "success": True,
        "data": {
            "account_id": account_id,
            "message": result.get("message", "Verified")
        }
    }


def _auth_status(params):
    account_id = params.getvalue("account_id", "").strip()

    if not account_id:
        return {
            "success": False,
            "error": {"code": 203, "message": "account_id required"}
        }

    account = config_manager.get_account(account_id)
    if not account:
        return {
            "success": False,
            "error": {"code": 204, "message": "Account not found"}
        }

    client = icloud_client.get_client(account_id, account["apple_id"])
    authenticated = client.restore_session()

    if authenticated:
        # Backfill authenticated_at if missing (e.g. account from before
        # we tracked this); don't overwrite a real timestamp with "now".
        updates = {"status": "authenticated"}
        if not account.get("authenticated_at"):
            updates["authenticated_at"] = int(time.time())
        config_manager.update_account(account_id, updates)
    else:
        config_manager.update_account(account_id, {"status": "re_auth_needed"})

    return {
        "success": True,
        "data": {
            "account_id": account_id,
            "authenticated": authenticated,
            "status": account.get("status", "unknown")
        }
    }
