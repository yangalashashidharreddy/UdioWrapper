"""
hCaptcha auto-solver for UdioWrapper.

Solves issue #7 (500 Server Error - Auto Solve hcaptcha).

Background
----------
Udio's ``/generate-proxy`` endpoint returns HTTP 500 (sometimes 403/503)
when its backend cannot verify a valid hCaptcha token. The web frontend
solves an *invisible* hCaptcha challenge and sends the resulting token
with the generation request. This module reproduces that step
programmatically via a third-party solving service.

Supported services (configured via constructor args or env vars):

  * 2captcha  : ``CAPTCHA_API_KEY`` / ``TWOCAPTCHA_API_KEY`` env var
  * Capsolver : ``CAPSOLVER_API_KEY`` env var
  * NopeCHA   : ``NOPECHA_API_KEY`` env var
  * custom    : any ``solver_callback(sitekey, site_url) -> token`` callable

If no API key / callback is configured the solver degrades gracefully: it
logs a hint and returns ``None`` so callers can still retry the request
without a token (preserving the pre-fix behaviour).

The Udio hCaptcha sitekey below was read from the live udio.com frontend
bundle (``/_next/static/chunks/*``).

Legal note: solving captchas against a site's anti-bot protection may
violate that site's Terms of Service. This module is provided for
educational/research purposes. Use at your own risk and respect Udio's ToS.
"""

import os
import time

import requests


# Invisible hCaptcha sitekey used by https://www.udio.com.
UDIO_HCAPTCHA_SITEKEY = "2945592b-1928-43a9-8473-7e7fed3d752e"
UDIO_SITE_URL = "https://www.udio.com"

# Body snippets that strongly suggest a captcha / anti-bot block.
_CAPTCHA_KEYWORDS = (
    "captcha",
    "hcaptcha",
    "h-captcha",
    "challenge",
    "challenge-error",
    "bot",
    "cloudflare",
    "verify you are human",
    "are you a robot",
    "access denied",
    "automated",
    "recaptcha",
)

_RETRYABLE_STATUS_CODES = (429, 500, 502, 503, 504)


def _normalize_service(service):
    """Normalize a user-provided service name to a canonical id."""
    if not service:
        return None
    s = str(service).strip().lower().replace("_", "").replace("-", "")
    if s in ("2captcha", "twocaptcha", "captcha"):
        return "2captcha"
    if s in ("capsolver", "capsolvercom", "cap"):
        return "capsolver"
    if s in ("nopecha", "nopechaio", "nope"):
        return "nopecha"
    return s


def _resolve_api_key_and_service(api_key=None, service=None):
    """Resolve API key + service from explicit args with env fallback.

    Precedence for the key (first non-empty wins):
      explicit arg > CAPTCHA_API_KEY > TWOCAPTCHA_API_KEY >
      CAPSOLVER_API_KEY > NOPECHA_API_KEY
    """
    env_2captcha = os.getenv("CAPTCHA_API_KEY") or os.getenv("TWOCAPTCHA_API_KEY") or os.getenv("TWO_CAPTCHA_API_KEY")
    env_capsolver = os.getenv("CAPSOLVER_API_KEY")
    env_nopecha = os.getenv("NOPECHA_API_KEY")

    resolved_service = _normalize_service(service)
    resolved_key = api_key

    if not resolved_key:
        # Infer service from whichever env var is set (unless explicitly given).
        if resolved_service == "2captcha":
            resolved_key = env_2captcha
        elif resolved_service == "capsolver":
            resolved_key = env_capsolver
        elif resolved_service == "nopecha":
            resolved_key = env_nopecha
        else:
            if env_2captcha:
                resolved_key = env_2captcha
                resolved_service = "2captcha"
            elif env_capsolver:
                resolved_key = env_capsolver
                resolved_service = "capsolver"
            elif env_nopecha:
                resolved_key = env_nopecha
                resolved_service = "nopecha"

    if not resolved_service:
        resolved_service = "2captcha"  # sensible default for error messages

    return resolved_key, resolved_service


class HCaptchaSolver:
    """Solve Udio's invisible hCaptcha challenge via an external service.

    Parameters
    ----------
    sitekey: str, optional
        hCaptcha sitekey. Defaults to Udio's sitekey.
    site_url: str, optional
        Page URL the challenge belongs to. Defaults to https://www.udio.com.
    api_key: str, optional
        Solving-service API key. Falls back to ``CAPTCHA_API_KEY`` /
        ``CAPSOLVER_API_KEY`` / ``NOPECHA_API_KEY`` env vars.
    service: str, optional
        One of ``"2captcha"``, ``"capsolver"``, ``"nopecha"``. Inferred
        from env vars when omitted.
    solver_callback: callable, optional
        Custom solver ``fn(sitekey, site_url) -> token``. Takes precedence
        over API-key services. Useful for manual solving or other vendors.
    timeout: int
        HTTP timeout (seconds) for solver API calls.
    poll_interval: int/float
        Seconds between solver result polls.
    max_polls: int
        Max polls before giving up on a solving task.
    """

    def __init__(
        self,
        sitekey=None,
        site_url=None,
        api_key=None,
        service=None,
        solver_callback=None,
        timeout=30,
        poll_interval=3,
        max_polls=40,
    ):
        self.sitekey = sitekey or UDIO_HCAPTCHA_SITEKEY
        self.site_url = site_url or UDIO_SITE_URL
        self.solver_callback = solver_callback
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.max_polls = max_polls
        self.api_key, self.service = _resolve_api_key_and_service(api_key, service)
        # Normalize once more in case env-derived value needs it.
        self.service = _normalize_service(self.service) or "2captcha"
        self._cache = None

    # -- cache ---------------------------------------------------------
    def clear_cache(self):
        """Drop any cached token (hCaptcha tokens are single-use)."""
        self._cache = None

    # -- public API ----------------------------------------------------
    def get_token(self, force=False):
        """Return a fresh hCaptcha token, or ``None`` if unavailable.

        Tokens are single-use and short-lived, so callers should request a
        fresh token (``force=True``) after each failed attempt and clear the
        cache after a successful request.
        """
        if self._cache and not force:
            return self._cache
        if self.solver_callback is not None:
            try:
                token = self.solver_callback(self.sitekey, self.site_url)
            except Exception as exc:  # never let solver kill the request
                print(f"hCaptcha: custom solver error: {exc}")
                return None
            if token:
                self._cache = token
            return token
        if not self.api_key:
            print(
                "hCaptcha: no solver configured. Set CAPTCHA_API_KEY (2captcha), "
                "CAPSOLVER_API_KEY (Capsolver) or NOPECHA_API_KEY (NopeCHA), "
                "pass captcha_api_key=..., or provide solver_callback=... "
                "to enable auto-solving."
            )
            return None
        token = None
        try:
            if self.service == "2captcha":
                token = self._solve_2captcha()
            elif self.service == "capsolver":
                token = self._solve_capsolver()
            elif self.service == "nopecha":
                token = self._solve_nopecha()
            else:
                print(
                    f"hCaptcha: unknown service '{self.service}'. "
                    "Use '2captcha', 'capsolver' or 'nopecha'."
                )
                return None
        except Exception as exc:  # never let a solver failure kill the request
            print(f"hCaptcha: solver error: {exc}")
            return None
        if token:
            self._cache = token
        return token

    # Backwards-friendly alias.
    def solve(self, force=False):
        return self.get_token(force=force)

    # -- 2captcha ------------------------------------------------------
    def _solve_2captcha(self):
        # Submit the challenge (JSON API, with legacy text fallback).
        resp = requests.post(
            "https://2captcha.com/in.php",
            data={
                "key": self.api_key,
                "method": "hcaptcha",
                "sitekey": self.sitekey,
                "pageurl": self.site_url,
                "json": 1,
            },
            timeout=self.timeout,
        )
        task_id = None
        try:
            payload = resp.json()
            if isinstance(payload, dict) and payload.get("status") == 1:
                task_id = str(payload.get("request"))
            else:
                err = payload.get("request") if isinstance(payload, dict) else resp.text
                print(f"hCaptcha: 2captcha submit failed: {err}")
                return None
        except ValueError:
            # Legacy plain-text API: "OK|<id>".
            text = resp.text.strip()
            if not text.startswith("OK|"):
                print(f"hCaptcha: 2captcha submit failed: {text[:200]}")
                return None
            task_id = text.split("|", 1)[1]

        # Poll for the result.
        for _ in range(self.max_polls):
            time.sleep(self.poll_interval)
            res = requests.get(
                "https://2captcha.com/res.php",
                params={"key": self.api_key, "action": "get", "id": task_id, "json": 1},
                timeout=self.timeout,
            )
            try:
                payload = res.json()
            except ValueError:
                text = res.text.strip()
                if text.startswith("OK|"):
                    return text.split("|", 1)[1]
                if text == "CAPCHA_NOT_READY":
                    continue
                print(f"hCaptcha: 2captcha error: {text[:200]}")
                return None
            if payload.get("status") == 1:
                return payload.get("request")
            request = payload.get("request")
            if request == "CAPCHA_NOT_READY":
                continue
            print(f"hCaptcha: 2captcha error: {request}")
            return None
        print("hCaptcha: 2captcha timed out waiting for solution.")
        return None

    # -- Capsolver -----------------------------------------------------
    def _solve_capsolver(self):
        payload = {
            "clientKey": self.api_key,
            "task": {
                "type": "HCaptchaTaskProxyLess",
                "websiteURL": self.site_url,
                "websiteKey": self.sitekey,
            },
        }
        try:
            resp = requests.post(
                "https://api.capsolver.com/createTask", json=payload, timeout=self.timeout
            )
            data = resp.json()
        except ValueError:
            print(f"hCaptcha: capsolver createTask bad response: {resp.text[:200]}")
            return None
        task_id = data.get("taskId")
        if not task_id:
            print(f"hCaptcha: capsolver createTask failed: {resp.text[:300]}")
            return None
        for _ in range(self.max_polls):
            time.sleep(self.poll_interval)
            try:
                status = requests.post(
                    "https://api.capsolver.com/getTaskResult",
                    json={"clientKey": self.api_key, "taskId": task_id},
                    timeout=self.timeout,
                ).json()
            except ValueError:
                continue
            if status.get("status") == "ready":
                return status.get("solution", {}).get("gRecaptchaResponse")
            if status.get("status") == "failed":
                print(f"hCaptcha: capsolver failed: {status}")
                return None
            if status.get("errorId"):
                print(f"hCaptcha: capsolver error: {status}")
                return None
        print("hCaptcha: capsolver timed out waiting for solution.")
        return None

    # -- NopeCHA -------------------------------------------------------
    def _solve_nopecha(self):
        # Submit: POST https://api.nopecha.com/token/ -> {"data": "<job-id>"}
        try:
            resp = requests.post(
                "https://api.nopecha.com/token/",
                json={
                    "key": self.api_key,
                    "type": "hcaptcha",
                    "sitekey": self.sitekey,
                    "url": self.site_url,
                },
                timeout=self.timeout,
            )
            data = resp.json()
        except ValueError:
            print(f"hCaptcha: nopecha submit bad response: {resp.text[:200]}")
            return None
        job_id = data.get("data")
        if not job_id:
            print(f"hCaptcha: nopecha submit failed: {resp.text[:300]}")
            return None
        # Poll: GET https://api.nopecha.com/token/?key=...&id=... -> {"data": token}
        for _ in range(self.max_polls):
            time.sleep(self.poll_interval)
            try:
                status = requests.get(
                    "https://api.nopecha.com/token/",
                    params={"key": self.api_key, "id": job_id},
                    timeout=self.timeout,
                ).json()
            except ValueError:
                continue
            if status.get("data"):
                return status["data"]
            # {"error": 14, "message": "Incomplete job"} means keep polling.
            if status.get("error") not in (None, 0, 14):
                print(f"hCaptcha: nopecha error: {status}")
                return None
        print("hCaptcha: nopecha timed out waiting for solution.")
        return None


def is_hcaptcha_blocked(response):
    """Heuristic: does this response indicate a missing/invalid captcha?

    Udio's backend answers with HTTP 500 (sometimes 403/503) when the
    hCaptcha token is missing or invalid, usually with an empty/generic
    body. We treat those statuses as captcha blocks, plus any response
    whose body mentions captcha/challenge/bot keywords.
    """
    if response is None:
        return False
    try:
        status_code = int(getattr(response, "status_code", 0) or 0)
    except (TypeError, ValueError):
        status_code = 0
    if status_code in (403, 500, 503):
        return True
    try:
        body = (response.text or "").lower()
    except Exception:
        return False
    if not body:
        return False
    return any(keyword in body for keyword in _CAPTCHA_KEYWORDS)


def is_retryable_status(status_code):
    """Return True for transient statuses worth retrying with backoff."""
    try:
        return int(status_code) in _RETRYABLE_STATUS_CODES
    except (TypeError, ValueError):
        return False
