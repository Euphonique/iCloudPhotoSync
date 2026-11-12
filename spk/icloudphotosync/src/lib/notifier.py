"""
Notification helper for the iCloud Photo Sync 3rd-party app.

Channels:
  - DSM desktop (always). Uses the documented DSM SPA mechanism:
    The app registers `texts: "texts"` and `preloadTexts: [...]` in ui/config
    so DSM loads ui/texts/<locale>/strings into the namespace
    `SYNO.SDS.iCloudPhotoSync.Instance`. We push notifications via
    `synodsmnotify -c <className> @recipient <title_key> <msg_key> [args]`.
    Title/msg keys use the form `<className>:<section>:<key>`. Positional
    args after the msg key fill `{0}`, `{1}` placeholders in the strings file.
  - Email via the app's own SMTP settings (optional).
  - Webhook (optional): generic JSON, ntfy or Discord.

DSM cannot deliver a 3rd-party notification by email: the `sysnotify`
resource worker that registers mail templates is reserved for
Synology-signed packages ("non-synology-signed package should not use
internal worker"), and the DSM SMTP password is stored encrypted. Hence the
separate SMTP configuration (#89).

Notifications are throttled per (account_id, kind) via marker files so the
scheduler tick doesn't spam the user every 60 seconds. Errors are always
swallowed -- a failed notification must never break the scheduler.
"""
import base64
import logging
import os
import re
import smtplib
import socket
import ssl
import subprocess
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

import config_manager

LOGGER = logging.getLogger("notifier")

NOTIFY_BIN = "/usr/syno/bin/synodsmnotify"
APP_CLASS = "SYNO.SDS.iCloudPhotoSync.Instance"

TEXTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "app", "texts")
SYNOINFO = "/etc/synoinfo.conf"

SMTP_SECRET_LABEL = "notify-smtp"
SMTP_SECURITY = ("starttls", "ssl", "none")
WEBHOOK_FORMATS = ("json", "ntfy", "discord")
HTTP_TIMEOUT = 20

DEFAULT_SETTINGS = {
    "email": {
        "enabled": False,
        "host": "",
        "port": 587,
        "security": "starttls",
        "username": "",
        "password_enc": "",
        "sender": "",
        "recipients": "",
    },
    "webhook": {
        "enabled": False,
        "url": "",
        "format": "json",
    },
}


# --- Settings -------------------------------------------------------------

def load_settings():
    """Notification settings from config.json merged over the defaults."""
    stored = (config_manager.load_config() or {}).get("notifications") or {}
    settings = {}
    for channel, defaults in DEFAULT_SETTINGS.items():
        merged = dict(defaults)
        merged.update(stored.get(channel) or {})
        settings[channel] = merged
    return settings


def smtp_password(email_cfg):
    return config_manager.decrypt_secret(
        SMTP_SECRET_LABEL, email_cfg.get("password_enc", "")) or ""


# --- Texts ----------------------------------------------------------------

def _dsm_language():
    """Language DSM uses for notification mails (maillang), else enu."""
    values = {}
    try:
        with open(SYNOINFO, "r", errors="replace") as f:
            for line in f:
                m = re.match(r'^(\w+)="?([^"]*)"?\s*$', line.strip())
                if m:
                    values[m.group(1)] = m.group(2)
    except OSError:
        pass
    for key in ("maillang", "language"):
        lang = values.get(key, "")
        if lang and lang != "def" and os.path.isdir(os.path.join(TEXTS_DIR, lang)):
            return lang
    return "enu"


def _load_texts(lang):
    """[notification] section of app/texts/<lang>/strings as a dict."""
    texts = {}
    path = os.path.join(TEXTS_DIR, lang, "strings")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            section = None
            for line in f:
                line = line.strip()
                if line.startswith("[") and line.endswith("]"):
                    section = line[1:-1]
                    continue
                if section != "notification":
                    continue
                m = re.match(r'^(\w+)\s*=\s*"(.*)"$', line)
                if m:
                    texts[m.group(1)] = m.group(2)
    except OSError:
        pass
    return texts


def render(title_key, msg_key, args=None):
    """Resolve a notification title/message in the DSM mail language."""
    texts = _load_texts(_dsm_language())
    if not texts:
        texts = _load_texts("enu")
    args = [str(a) for a in (args or [])]

    def fill(text):
        return re.sub(r"\{(\d+)\}",
                      lambda m: args[int(m.group(1))] if int(m.group(1)) < len(args) else m.group(0),
                      text)

    return fill(texts.get(title_key, title_key)), fill(texts.get(msg_key, msg_key))


# --- Channels -------------------------------------------------------------

def _send_desktop(title_key, msg_key, args):
    if not os.path.exists(NOTIFY_BIN):
        LOGGER.warning("synodsmnotify not found at %s; skipping notification", NOTIFY_BIN)
        return False
    cmd = [
        NOTIFY_BIN, "-c", APP_CLASS,
        "@administrators",
        APP_CLASS + ":notification:" + title_key,
        APP_CLASS + ":notification:" + msg_key,
    ]
    if args:
        cmd.extend(str(a) for a in args)
    subprocess.run(cmd, timeout=10, check=False)
    return True


def send_email(email_cfg, subject, body, password=None):
    """Send a plain-text mail. Raises on any SMTP/network error."""
    recipients = [r.strip() for r in re.split(r"[,;\s]+", email_cfg.get("recipients", "")) if r.strip()]
    if not email_cfg.get("host") or not recipients:
        raise ValueError("SMTP server and recipient are required")
    if password is None:
        password = smtp_password(email_cfg)
    username = email_cfg.get("username", "")
    sender = email_cfg.get("sender") or username or "icloudphotosync@" + socket.gethostname()

    msg = EmailMessage()
    msg["Subject"] = "[%s] %s" % (socket.gethostname(), subject)
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=socket.gethostname())
    msg.set_content(body)

    host = email_cfg["host"]
    port = int(email_cfg.get("port") or 0)
    security = email_cfg.get("security", "starttls")
    context = ssl.create_default_context()
    if security == "ssl":
        server = smtplib.SMTP_SSL(host, port or 465, timeout=HTTP_TIMEOUT, context=context)
    else:
        server = smtplib.SMTP(host, port or 587, timeout=HTTP_TIMEOUT)
    try:
        if security == "starttls":
            server.starttls(context=context)
        if username:
            server.login(username, password)
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except Exception:
            pass


def send_webhook(webhook_cfg, title, message, event="", apple_id=""):
    """POST the notification to the configured URL. Raises on failure."""
    import requests

    url = webhook_cfg.get("url", "")
    if not re.match(r"^https?://", url):
        raise ValueError("Webhook URL must start with http:// or https://")
    fmt = webhook_cfg.get("format", "json")
    if fmt == "ntfy":
        # HTTP headers are latin-1; ntfy decodes RFC 2047 encoded words.
        encoded_title = "=?UTF-8?B?%s?=" % base64.b64encode(title.encode("utf-8")).decode("ascii")
        resp = requests.post(url, data=message.encode("utf-8"), timeout=HTTP_TIMEOUT,
                             headers={"Title": encoded_title, "Tags": "cloud"})
    elif fmt == "discord":
        resp = requests.post(url, json={"content": "**%s**\n%s" % (title, message)},
                             timeout=HTTP_TIMEOUT)
    else:
        resp = requests.post(url, timeout=HTTP_TIMEOUT, json={
            "title": title,
            "message": message,
            "event": event,
            "apple_id": apple_id,
            "hostname": socket.gethostname(),
        })
    if resp.status_code >= 400:
        raise RuntimeError("HTTP %d: %s" % (resp.status_code, resp.text[:200]))


def _send_external(kind, title_key, msg_key, args, apple_id):
    """Email / webhook delivery; failures are logged, never raised."""
    settings = load_settings()
    if not (settings["email"]["enabled"] or settings["webhook"]["enabled"]):
        return
    title, message = render(title_key, msg_key, args)
    if settings["email"]["enabled"]:
        try:
            send_email(settings["email"], title, message)
            LOGGER.warning("Sent %s notification by email", kind)
        except Exception as e:
            LOGGER.error("Email notification (%s) failed: %s", kind, e)
    if settings["webhook"]["enabled"]:
        try:
            send_webhook(settings["webhook"], title, message, event=kind, apple_id=apple_id)
            LOGGER.warning("Sent %s notification by webhook", kind)
        except Exception as e:
            LOGGER.error("Webhook notification (%s) failed: %s", kind, e)


# --- Public API -----------------------------------------------------------

def _marker_path(account_id, kind):
    return os.path.join(config_manager.get_account_dir(account_id), ".notif_" + kind)


def notify(account_id, kind, title_key, msg_key, args=None, throttle_hours=24,
           apple_id=""):
    """Send a notification on every enabled channel.

    `kind` is a short identifier used for the throttle marker filename and
    the webhook `event` field (e.g. "reauth", "expiring"). `title_key` /
    `msg_key` are the keys inside the `[notification]` section of
    app/texts/<locale>/strings. `args` is an optional list of positional
    substitutions for {0}, {1}, ... in the msg.
    """
    marker = _marker_path(account_id, kind)
    try:
        if os.path.isfile(marker):
            age = time.time() - os.path.getmtime(marker)
            if age < throttle_hours * 3600:
                return False
    except OSError:
        pass

    try:
        _send_desktop(title_key, msg_key, args)
        _send_external(kind, title_key, msg_key, args, apple_id)
        with open(marker, "w") as f:
            f.write(str(int(time.time())))
        LOGGER.info("Sent notification (%s) for account %s", kind, account_id)
        return True
    except Exception:
        LOGGER.exception("Failed to send notification (%s) for %s", kind, account_id)
        return False


def clear_marker(account_id, kind):
    """Remove a throttle marker so the next notify() will fire again."""
    try:
        os.remove(_marker_path(account_id, kind))
    except OSError:
        pass


def clear_all_markers(account_id):
    """Clear every notification marker for an account (e.g. after re-auth)."""
    acc_dir = config_manager.get_account_dir(account_id)
    try:
        for name in os.listdir(acc_dir):
            if name.startswith(".notif_"):
                try:
                    os.remove(os.path.join(acc_dir, name))
                except OSError:
                    pass
    except OSError:
        pass
