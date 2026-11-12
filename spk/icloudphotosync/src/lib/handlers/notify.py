"""
Notify Handler — email / webhook notification settings (global, all accounts).

Actions:
  get   — Current settings (the SMTP password is never returned)
  set   — Save settings; an empty password keeps the stored one
  test  — Send a test message on one channel using the submitted settings
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import config_manager
import notifier


def handle(params):
    action = params.getvalue("action", "")
    if action == "get":
        return _get(params)
    if action == "set":
        return _set(params)
    if action == "test":
        return _test(params)
    return {"success": False, "error": {"code": 101, "message": "Unknown action"}}


def _public(settings):
    email = dict(settings["email"])
    email["has_password"] = bool(email.pop("password_enc", ""))
    return {"email": email, "webhook": dict(settings["webhook"])}


def _get(params):
    return {"success": True, "data": _public(notifier.load_settings())}


def _parse(params):
    """Validate submitted settings. Returns (settings, new_password, error)."""
    try:
        data = json.loads(params.getvalue("settings", "") or "{}")
    except ValueError:
        return None, None, "Invalid settings"
    email_in = data.get("email") or {}
    webhook_in = data.get("webhook") or {}

    current = notifier.load_settings()
    email = current["email"]
    webhook = current["webhook"]

    email["enabled"] = bool(email_in.get("enabled"))
    email["host"] = str(email_in.get("host", "")).strip()
    try:
        email["port"] = int(email_in.get("port") or 0)
    except (TypeError, ValueError):
        return None, None, "Invalid SMTP port"
    if not 0 <= email["port"] <= 65535:
        return None, None, "Invalid SMTP port"
    security = email_in.get("security", "starttls")
    if security not in notifier.SMTP_SECURITY:
        return None, None, "Invalid SMTP security"
    email["security"] = security
    email["username"] = str(email_in.get("username", "")).strip()
    email["sender"] = str(email_in.get("sender", "")).strip()
    email["recipients"] = str(email_in.get("recipients", "")).strip()
    new_password = email_in.get("password") or None
    if email_in.get("clear_password"):
        email["password_enc"] = ""

    webhook["enabled"] = bool(webhook_in.get("enabled"))
    webhook["url"] = str(webhook_in.get("url", "")).strip()
    fmt = webhook_in.get("format", "json")
    if fmt not in notifier.WEBHOOK_FORMATS:
        return None, None, "Invalid webhook format"
    webhook["format"] = fmt

    if email["enabled"] and (not email["host"] or not email["recipients"]):
        return None, None, "SMTP server and recipient are required"
    if webhook["enabled"] and not webhook["url"].startswith(("http://", "https://")):
        return None, None, "Webhook URL must start with http:// or https://"

    return {"email": email, "webhook": webhook}, new_password, None


def _set(params):
    settings, new_password, error = _parse(params)
    if error:
        return {"success": False, "error": {"code": 402, "message": error}}
    if new_password:
        settings["email"]["password_enc"] = config_manager.encrypt_secret(
            notifier.SMTP_SECRET_LABEL, new_password)
    cfg = config_manager.load_config()
    cfg["notifications"] = settings
    config_manager.save_config(cfg)
    return {"success": True, "data": _public(settings)}


def _test(params):
    """Send a test on one channel with the form values, saved or not."""
    channel = params.getvalue("channel", "")
    settings, new_password, error = _parse(params)
    if error:
        return {"success": False, "error": {"code": 402, "message": error}}
    title, message = notifier.render("test_title", "test_msg")
    try:
        if channel == "email":
            password = new_password if new_password else notifier.smtp_password(settings["email"])
            notifier.send_email(settings["email"], title, message, password=password)
        elif channel == "webhook":
            notifier.send_webhook(settings["webhook"], title, message, event="test")
        else:
            return {"success": False, "error": {"code": 101, "message": "Unknown channel"}}
    except Exception as e:
        return {"success": False, "error": {"code": 500, "message": "%s: %s" % (type(e).__name__, e)}}
    return {"success": True, "data": {}}
