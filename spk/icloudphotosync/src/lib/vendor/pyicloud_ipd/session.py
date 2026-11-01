"""pyicloud_ipd session — simplified from icloudpd v1.32.2."""
import inspect
import json
import logging
import os

from requests import Session

from pyicloud_ipd.exceptions import (
    PyiCloud2SARequiredException,
    PyiCloudADPProtectionException,
    PyiCloudAPIResponseException,
    PyiCloudServiceNotActivatedException,
    PyiCloudServiceUnavailableException,
    PyiCloudSessionExpiredException,
)

LOGGER = logging.getLogger(__name__)

HEADER_DATA = {
    "X-Apple-ID-Account-Country": "account_country",
    "X-Apple-ID-Session-Id": "session_id",
    "X-Apple-Session-Token": "session_token",
    "X-Apple-TwoSV-Trust-Token": "trust_token",
    "X-Apple-TwoSV-Trust-Eligible": "trust_eligible",
    "X-Apple-I-Rscd": "apple_rscd",
    "X-Apple-I-Ercd": "apple_ercd",
    "scnt": "scnt",
}


class PyiCloudPasswordFilter(logging.Filter):
    def __init__(self, password):
        super().__init__(password)

    def filter(self, record):
        message = record.getMessage()
        if self.name in message:
            record.msg = message.replace(self.name, "********")
            record.args = []
        return True


class PyiCloudSession(Session):
    """iCloud session with Apple auth header extraction and error handling."""

    def __init__(self, service):
        self.service = service
        super().__init__()

    def request(self, method, url, _auth_retry=True, **kwargs):
        # Charge logging to the right service endpoint
        try:
            callee = inspect.stack()[2]
            module = inspect.getmodule(callee[0])
            mod_name = module.__name__ if module else __name__
        except Exception:
            mod_name = __name__
        request_logger = logging.getLogger(mod_name).getChild("http")
        if (
            self.service.password_filter
            and self.service.password_filter not in request_logger.filters
        ):
            request_logger.addFilter(self.service.password_filter)

        request_logger.debug("%s %s %s", method, url, kwargs.get("data", ""))

        if "timeout" not in kwargs and self.service.http_timeout is not None:
            kwargs["timeout"] = self.service.http_timeout

        response = super().request(method, url, **kwargs)

        # Handle 503
        if response.status_code == 503:
            raise PyiCloudServiceUnavailableException(
                "Apple iCloud is temporarily refusing requests"
            )

        content_type = response.headers.get("Content-Type", "").split(";")[0]
        json_mimetypes = ["application/json", "text/json"]

        # Extract Apple auth headers into session_data
        for header, value in HEADER_DATA.items():
            if response.headers.get(header):
                self.service.session_data[value] = response.headers.get(header)

        try:
            os.makedirs(os.path.dirname(self.service.session_path),
                        mode=0o700, exist_ok=True)
            with open(self.service.session_path, "w", encoding="utf-8") as f:
                json.dump(self.service.session_data, f)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
            try:
                os.chmod(self.service.session_path, 0o600)
            except OSError:
                pass
        except Exception:
            LOGGER.warning("Failed to save session data to %s",
                           self.service.session_path, exc_info=True)

        # Save cookies
        try:
            self.cookies.save(ignore_discard=True, ignore_expires=True)
            try:
                os.chmod(self.cookies.filename, 0o600)
            except OSError:
                pass
        except Exception:
            LOGGER.warning("Failed to save cookies to %s",
                           self.cookies.filename, exc_info=True)

        # CloudKit answers 401 AUTHENTICATION_FAILED ("no auth method found")
        # once the short-lived WEBAUTH cookies have expired, even though
        # /validate still accepts the session. accountLogin with the stored
        # session token mints fresh cookies — retry the request once.
        if (response.status_code == 401 and _auth_retry
                and "ckdatabasews" in url
                and self.service.session_data.get("session_token")):
            LOGGER.info("CloudKit rejected the web session (401) — "
                        "refreshing cookies via accountLogin and retrying")
            try:
                self.service.refresh_web_session()
            except Exception:
                LOGGER.warning("Web session refresh failed", exc_info=True)
            else:
                return self.request(method, url, _auth_retry=False, **kwargs)

        if not response.ok and (
            content_type not in json_mimetypes or response.status_code in [421, 450, 500]
        ):
            self._log_error_response(request_logger, response)
            self._raise_error(str(response.status_code), response.reason)

        if content_type not in json_mimetypes:
            if self.service.session_data.get("apple_rscd") == "401":
                self._raise_error("401", "Invalid username/password combination.")
            return response

        try:
            data = response.json() if response.status_code != 204 else {}
        except ValueError:
            request_logger.warning("Failed to parse response with JSON mimetype")
            return response

        if isinstance(data, dict):
            if data.get("hasError"):
                errors = data.get("service_errors")
                code = None
                reason = None
                if errors:
                    code = errors[0].get("code")
                    reason = errors[0].get("message")
                self._log_error_response(request_logger, response, code, reason)
                self._raise_error(code or "Unknown", reason or "Unknown")
            elif not data.get("success"):
                reason = data.get("errorMessage")
                reason = reason or data.get("reason")
                reason = reason or data.get("errorReason")
                if not reason and isinstance(data.get("error"), str):
                    reason = data.get("error")
                if not reason and data.get("error"):
                    reason = "Unknown reason"

                code = data.get("errorCode")
                if not code and data.get("serverErrorCode"):
                    code = data.get("serverErrorCode")
                if not code and data.get("error"):
                    code = data.get("error")

                if reason:
                    self._log_error_response(request_logger, response, code, reason)
                    self._raise_error(code or "Unknown", reason)

        return response

    @staticmethod
    def _log_error_response(logger, response, code=None, reason=None):
        body = ""
        try:
            body = response.text[:1000]
        except Exception:
            pass
        logger.warning(
            "Apple API error: %s %s → HTTP %d | code=%s reason=%s | body=%s",
            response.request.method, response.url,
            response.status_code,
            code or "-", reason or "-",
            body or "(empty)"
        )

    def _raise_error(self, code, reason):
        if (
            self.service.requires_2sa
            and reason == "Missing X-APPLE-WEBAUTH-TOKEN cookie"
        ):
            raise PyiCloud2SARequiredException(self.service.apple_id)
        if code == "AUTHENTICATION_FAILED":
            raise PyiCloudSessionExpiredException(
                "Apple rejected the iCloud session (%s). Please sign in "
                "again in iCloud Photo Sync. If this keeps happening, sign "
                "in once at icloud.com/photos in a browser and check that "
                "'Access iCloud Data on the Web' is enabled for this Apple "
                "ID." % (reason or "no auth method found"), code)
        if code == "ZONE_NOT_FOUND":
            reason = (
                "Please log into https://icloud.com/ to manually "
                "finish setting up your iCloud service"
            )
            raise PyiCloudServiceNotActivatedException(reason, code)
        if code == "ACCESS_DENIED":
            reason_lower = (reason or "").lower()
            if any(kw in reason_lower for kw in (
                "private database", "private db", "not accessible",
                "not available", "end-to-end", "advanced data protection",
                "disabled for this account",
            )):
                raise PyiCloudADPProtectionException(reason)
            reason = (
                reason + ". Please wait a few minutes then try again. "
                "The remote servers might be trying to throttle requests."
            )
        if code in ["421", "450", "500"]:
            reason = "Authentication required for Account."
        if code == "Unknown" and reason in ("Unknown", "Unknown reason"):
            reason = (
                "Apple returned an unrecognized error. This is usually "
                "temporary — try logging out and back in. If it persists, "
                "check the package log for details."
            )

        raise PyiCloudAPIResponseException(reason, code)
