"""Live check for Udio hCaptcha issue #7.

Runs a real POST to https://www.udio.com/api/generate-proxy WITHOUT spending
a solver credit first, and reports whether you hit the captcha block.

Usage (on YOUR machine, not this sandbox — sandbox IPs are blocked by Udio):
    export UDIO_AUTH_TOKEN="paste sb-api-auth-token cookie value"
    # optional, only if you want auto-solve on the 2nd attempt:
    export CAPTCHA_API_KEY="your 2captcha key"        # or CAPSOLVER_API_KEY / NOPECHA_API_KEY
    python3 live_check.py
    python3 live_check.py --with-solver   # retry with solver if blocked

Never paste your real tokens into chat. Keep them in env vars.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from udio_wrapper import UdioWrapper
from udio_wrapper.hcaptcha_solver import is_hcaptcha_blocked


def main():
    with_solver = "--with-solver" in sys.argv
    auth = os.getenv("UDIO_AUTH_TOKEN", "").strip()
    if not auth or auth.startswith("paste"):
        print("ERROR: set UDIO_AUTH_TOKEN env var first:")
        print('  export UDIO_AUTH_TOKEN="your sb-api-auth-token value"')
        return 2

    print(f"Auth token length: {len(auth)} chars (prefix {auth[:8]}...)")
    if with_solver:
        print("Mode: WITH solver (will auto-solve if blocked)")
        w = UdioWrapper(auth)
    else:
        print("Mode: WITHOUT solver (1 attempt, no retry — pure diagnosis)")
        w = UdioWrapper(auth, max_retries=0)

    url = f"{w.API_BASE_URL}/generate-proxy"
    headers = w.get_headers()
    data = {"prompt": "Relaxing jazz test", "samplerOptions": {"seed": -1}}

    print(f"POST {url} ...")
    try:
        import requests
        resp = requests.post(url, headers=headers, json=data, timeout=30)
    except Exception as e:
        print(f"NETWORK ERROR (no HTTP response): {type(e).__name__}: {e}")
        print("If this is SSL/TLS EOF in a cloud sandbox, run this script on your own machine instead.")
        return 3

    body = (resp.text or "")[:600]
    print(f"Status: {resp.status_code}")
    print(f"Body (first 600 chars): {body or '<empty>'}")
    print(f"is_hcaptcha_blocked: {is_hcaptcha_blocked(resp)}")

    if resp.status_code == 200:
        print("RESULT: OK — no captcha block right now.")
        return 0
    if resp.status_code == 401:
        print("RESULT: AUTH EXPIRED — refresh sb-api-auth-token cookie and retry.")
        return 4
    if is_hcaptcha_blocked(resp):
        print("RESULT: CAPTCHA BLOCK (issue #7 reproduced).")
        if not with_solver:
            print("Re-run with --with-solver + CAPTCHA_API_KEY to test auto-solve.")
        return 5
    print(f"RESULT: other HTTP {resp.status_code} — see body above.")
    return 6


if __name__ == "__main__":
    raise SystemExit(main())
