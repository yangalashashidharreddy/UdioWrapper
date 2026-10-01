"""
Udio Wrapper
Author: Flowese
Version: 0.0.4
Date: 2024-04-15 (hCaptcha fix: 2026)
Description: Generates songs using the Udio API using textual prompts.

Issue #7 fix: Udio's /generate-proxy returns HTTP 500 when the backend
cannot verify a valid hCaptcha token. This wrapper now detects that
(and 403/503), auto-solves the invisible hCaptcha challenge when a
solving service is configured, injects the token, and retries with
backoff. Without a solver it still retries transient errors and prints
an actionable hint, so existing code keeps working unchanged.
"""

import os
import re
import time

import requests

from .hcaptcha_solver import (
    HCaptchaSolver,
    UDIO_HCAPTCHA_SITEKEY,
    UDIO_SITE_URL,
    is_hcaptcha_blocked,
    is_retryable_status,
)

__all__ = [
    "UdioWrapper",
    "UdioError",
    "UdioAuthError",
    "UdioCaptchaError",
    "HCaptchaSolver",
    "UDIO_HCAPTCHA_SITEKEY",
    "UDIO_SITE_URL",
]

__version__ = "0.0.4"


class UdioError(Exception):
    """Base error for UdioWrapper failures."""


class UdioAuthError(UdioError):
    """Raised when the auth token is missing/expired (HTTP 401)."""


class UdioCaptchaError(UdioError):
    """Raised when generation is blocked by hCaptcha and solving failed."""


def _inject_captcha_token(headers, data, token):
    """Return (headers, data) copies with the hCaptcha token injected.

    Udio's frontend/backend contract has shifted over time, and different
    reverse-engineered clients report different field names, so we inject
    all known variants. Unknown fields are ignored by the backend.
    """
    headers = dict(headers or {})
    headers["h-captcha-response"] = token
    # Alias used by some proxies / older clients.
    headers["x-hcaptcha-response"] = token

    if isinstance(data, dict):
        data = dict(data)
        data["captchaToken"] = token
        data["captcha_token"] = token
        data["h-captcha-response"] = token
    return headers, data


def _sanitize_filename(name, default="song"):
    """Make a string safe to use as a file name."""
    if not name:
        return default
    # Strip path separators and characters illegal on Windows/macOS.
    cleaned = re.sub(r'[\\\\/:*?"<>|]+', "_", str(name)).strip().strip(".")
    # Collapse whitespace, limit length.
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > 120:
        cleaned = cleaned[:120].rstrip()
    return cleaned or default


class UdioWrapper:
    API_BASE_URL = "https://www.udio.com/api"

    def __init__(
        self,
        auth_token,
        captcha_api_key=None,
        captcha_service=None,
        capsolver_api_key=None,
        nopecha_api_key=None,
        captcha_token=None,
        captcha_solver=None,
        solver_callback=None,
        max_retries=3,
        request_timeout=30,
        raise_on_error=False,
    ):
        """Create a wrapper bound to a Udio auth token.

        Parameters
        ----------
        auth_token: str
            Value of the ``sb-api-auth-token`` cookie from udio.com.
        captcha_api_key: str, optional
            API key for the captcha solving service (2captcha by default).
            Falls back to ``CAPTCHA_API_KEY`` / ``CAPSOLVER_API_KEY`` /
            ``NOPECHA_API_KEY`` env vars.
        captcha_service: str, optional
            One of ``"2captcha"``, ``"capsolver"``, ``"nopecha"``.
            Inferred from env vars when omitted.
        capsolver_api_key / nopecha_api_key: str, optional
            Convenience aliases for ``captcha_api_key`` with the service
            pinned to Capsolver / NopeCHA.
        captcha_token: str, optional
            A manually-solved hCaptcha token to use immediately (useful
            when you solve the challenge once in a browser and paste the
            ``h-captcha-response`` value here). Single-use.
        captcha_solver: HCaptchaSolver, optional
            Pre-configured solver instance. Takes precedence over API keys.
        solver_callback: callable, optional
            Custom solver ``fn(sitekey, site_url) -> token``. Takes
            precedence over API-key services.
        max_retries: int
            Retries after the first attempt for captcha blocks / transient
            errors (default 3, i.e. up to 4 attempts total).
        request_timeout: int/float
            HTTP timeout in seconds for Udio API calls.
        raise_on_error: bool
            If True, raise :class:`UdioError` subclasses instead of
            returning ``None`` on failure. Default False (legacy behaviour).
        """
        self.auth_token = auth_token
        self.all_track_ids = []
        self.max_retries = max(0, int(max_retries))
        self.request_timeout = request_timeout
        self.raise_on_error = bool(raise_on_error)
        self._manual_captcha_token = captcha_token

        if captcha_solver is not None and isinstance(captcha_solver, HCaptchaSolver):
            self._captcha_solver = captcha_solver
        else:
            # Resolve convenience aliases.
            resolved_key = captcha_api_key
            resolved_service = captcha_service
            if capsolver_api_key and not resolved_key:
                resolved_key = capsolver_api_key
                resolved_service = resolved_service or "capsolver"
            if nopecha_api_key and not resolved_key:
                resolved_key = nopecha_api_key
                resolved_service = resolved_service or "nopecha"
            # A raw callable passed as captcha_solver is treated as callback.
            callback = solver_callback
            if callable(captcha_solver):
                callback = captcha_solver
            self._captcha_solver = HCaptchaSolver(
                api_key=resolved_key,
                service=resolved_service,
                solver_callback=callback,
            )

    # -- captcha helpers ------------------------------------------------
    def set_captcha_token(self, token):
        """Set a manually-solved hCaptcha token for the next request(s)."""
        self._manual_captcha_token = token

    def clear_captcha_token(self):
        """Clear any manual token and the solver cache."""
        self._manual_captcha_token = None
        if self._captcha_solver is not None:
            self._captcha_solver.clear_cache()

    def _fail(self, message, exc_type=UdioError, original=None):
        print(message)
        if self.raise_on_error:
            if original is not None and isinstance(original, Exception):
                raise exc_type(message) from original
            raise exc_type(message)
        return None

    # -- HTTP layer ------------------------------------------------------
    def make_request(self, url, method, data=None, headers=None, max_retries=None, timeout=None):
        """Perform an HTTP request with hCaptcha auto-solve + retries.

        Strategy (lazy solving to avoid unnecessary solve costs):
          1. Try once *without* a captcha token (legacy behaviour).
          2. If the response looks like a captcha block (403/500/503 or
             captcha keywords in the body), solve a fresh token, inject it
             as header + payload fields, and retry with backoff.
          3. Retry other transient statuses (429/502/504) with backoff.
          4. Fail fast on 401 with an auth-token hint (no captcha retry).
        """
        if max_retries is None:
            max_retries = self.max_retries
        max_retries = max(0, int(max_retries))
        timeout = timeout if timeout is not None else self.request_timeout

        # Manual token (if any) is used from the first attempt.
        captcha_token = self._manual_captcha_token
        last_error = None

        for attempt in range(max_retries + 1):
            request_headers, request_data = _inject_captcha_token(headers, data, captcha_token) if captcha_token else (dict(headers or {}), data)

            try:
                if method == "POST":
                    response = requests.post(
                        url, headers=request_headers, json=request_data, timeout=timeout
                    )
                else:
                    response = requests.get(url, headers=request_headers, timeout=timeout)
            except requests.exceptions.RequestException as e:
                last_error = e
                if attempt < max_retries:
                    backoff = (attempt + 1) * 2
                    print(
                        f"Request error on {url} "
                        f"(attempt {attempt + 1}/{max_retries + 1}): {e}. "
                        f"Retrying in {backoff}s..."
                    )
                    time.sleep(backoff)
                    continue
                return self._fail(f"Error making {method} request to {url}: {e}", original=e)

            status = int(getattr(response, "status_code", 0) or 0)

            # --- 401: auth token invalid/expired -> fail fast with hint ---
            if status == 401:
                body = _safe_body_snippet(response)
                return self._fail(
                    "Udio auth failed (HTTP 401). Your `sb-api-auth-token` cookie "
                    "is missing or expired. Sign in at https://www.udio.com, copy "
                    "the fresh `sb-api-auth-token` cookie value (DevTools > "
                    f"Application > Cookies), and retry. Body: {body}",
                    exc_type=UdioAuthError,
                )

            # --- Captcha block -> solve + retry ---
            if is_hcaptcha_blocked(response) and attempt < max_retries:
                print(
                    f"hCaptcha block detected: HTTP {status} on {url} "
                    f"(attempt {attempt + 1}/{max_retries + 1})."
                )
                fresh_token = None
                try:
                    if self._captcha_solver is not None:
                        fresh_token = self._captcha_solver.get_token(force=True)
                except Exception as exc:  # solver must never crash requests
                    print(f"hCaptcha: solver raised: {exc}")
                    fresh_token = None

                if fresh_token:
                    captcha_token = fresh_token
                    # A manual token is single-use; consume it.
                    self._manual_captcha_token = None
                    print("hCaptcha: token solved, retrying with token...")
                else:
                    print(
                        "hCaptcha: no token available. Retrying without a token; "
                        "if this keeps failing with 500, configure a solver: "
                        "UdioWrapper(auth_token, captcha_api_key='YOUR_2CAPTCHA_KEY') "
                        "or set CAPTCHA_API_KEY / CAPSOLVER_API_KEY / NOPECHA_API_KEY, "
                        "or pass captcha_token='<manually-solved-token>'."
                    )
                time.sleep(2 * (attempt + 1))
                continue

            # --- Other transient statuses -> retry with backoff ---
            if status in (429, 502, 504) and attempt < max_retries:
                retry_after = _parse_retry_after(response)
                backoff = retry_after if retry_after is not None else (attempt + 1) * 3
                reason = "rate limited (429)" if status == 429 else f"transient {status}"
                print(
                    f"Udio {reason} on {url} "
                    f"(attempt {attempt + 1}/{max_retries + 1}). "
                    f"Retrying in {backoff}s..."
                )
                time.sleep(backoff)
                continue

            # --- Terminal response ---
            try:
                response.raise_for_status()
            except requests.exceptions.HTTPError as e:
                last_error = e
                # Retry generic 5xx once more if attempts remain.
                if status >= 500 and attempt < max_retries and is_retryable_status(status):
                    backoff = (attempt + 1) * 2
                    print(
                        f"Server error {status} on {url} "
                        f"(attempt {attempt + 1}/{max_retries + 1}): {e}. "
                        f"Retrying in {backoff}s..."
                    )
                    time.sleep(backoff)
                    continue
                body = _safe_body_snippet(response)
                hint = ""
                if status in (403, 500, 503):
                    hint = (
                        " This usually means Udio's hCaptcha check failed (issue #7). "
                        "Configure a solver (captcha_api_key=...) or pass a manually "
                        "solved captcha_token=..., refresh your auth token, and retry."
                    )
                return self._fail(
                    f"Error making {method} request to {url}: {e}. Body: {body}.{hint}",
                    exc_type=UdioCaptchaError if status in (403, 500, 503) else UdioError,
                    original=e,
                )

            # Success: hCaptcha tokens are single-use -> never reuse a cached one.
            if captcha_token and self._captcha_solver is not None:
                self._captcha_solver.clear_cache()
            if captcha_token == self._manual_captcha_token:
                self._manual_captcha_token = None
            return response

        return self._fail(
            f"Error making {method} request to {url}: retries exhausted. Last error: {last_error}",
            original=last_error if isinstance(last_error, Exception) else None,
        )

    def get_headers(self, get_request=False):
        headers = {
            "Accept": "application/json, text/plain, */*" if get_request else "application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/json",
            "Cookie": f"sb-api-auth-token={self.auth_token}",
            "Origin": "https://www.udio.com",
            "Referer": "https://www.udio.com/my-creations",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
        }
        if not get_request:
            headers.update(
                {
                    "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": '"macOS"',
                }
            )
        return headers

    def create_complete_song(self, short_prompt, extend_prompts, outro_prompt, seed=-1, custom_lyrics_short=None, custom_lyrics_extend=None, custom_lyrics_outro=None, num_extensions=1):
        print("Starting the generation of the complete song sequence...")

        # Generate the short song
        print("Generating the short song...")
        short_song_result = self.create_song(short_prompt, seed, custom_lyrics_short)
        if not short_song_result:
            print("Error generating the short song.")
            return None

        last_song_result = short_song_result
        extend_song_results = []

        # Generate the extend songs
        for i in range(num_extensions):
            if i < len(extend_prompts):
                prompt = extend_prompts[i]
                lyrics = custom_lyrics_extend[i] if custom_lyrics_extend and i < len(custom_lyrics_extend) else None
            else:
                prompt = extend_prompts[-1]  # Reuse the last prompt if not enough are provided
                lyrics = custom_lyrics_extend[-1] if custom_lyrics_extend else None

            print(f"Generating extend song {i + 1}...")
            try:
                conditioning_path = last_song_result[0]["song_path"]
                conditioning_id = last_song_result[0]["id"]
            except (IndexError, KeyError, TypeError):
                print(f"Error generating extend song {i + 1}: previous result missing song_path/id.")
                return None
            extend_song_result = self.extend(
                prompt,
                seed,
                audio_conditioning_path=conditioning_path,
                audio_conditioning_song_id=conditioning_id,
                custom_lyrics=lyrics,
            )
            if not extend_song_result:
                print(f"Error generating extend song {i + 1}.")
                return None

            extend_song_results.append(extend_song_result)
            last_song_result = extend_song_result

        # Generate the outro
        print("Generating the outro...")
        try:
            conditioning_path = last_song_result[0]["song_path"]
            conditioning_id = last_song_result[0]["id"]
        except (IndexError, KeyError, TypeError):
            print("Error generating the outro: previous result missing song_path/id.")
            return None
        outro_song_result = self.add_outro(
            outro_prompt,
            seed,
            audio_conditioning_path=conditioning_path,
            audio_conditioning_song_id=conditioning_id,
            custom_lyrics=custom_lyrics_outro,
        )
        if not outro_song_result:
            print("Error generating the outro.")
            return None

        print("Complete song sequence generated and processed successfully.")
        return {
            "short_song": short_song_result,
            "extend_songs": extend_song_results,
            "outro_song": outro_song_result,
        }

    def create_song(self, prompt, seed=-1, custom_lyrics=None):
        song_result = self.generate_song(prompt, seed, custom_lyrics)
        if not song_result:
            return None
        track_ids = song_result.get("track_ids", []) or []
        if not track_ids:
            print(f"No track_ids in generate response: {song_result}")
            return self._fail(
                "Udio returned no track_ids. This often follows a captcha block "
                "(HTTP 500 on /generate-proxy) or a rejected prompt. See above "
                "for hCaptcha/auth hints.",
                exc_type=UdioCaptchaError,
            )
        self.all_track_ids.extend(track_ids)
        return self.process_songs(track_ids, "short_songs")

    def extend(self, prompt, seed=-1, audio_conditioning_path=None, audio_conditioning_song_id=None, custom_lyrics=None):
        extend_song_result = self.generate_extend_song(
            prompt, seed, audio_conditioning_path, audio_conditioning_song_id, custom_lyrics
        )
        if not extend_song_result:
            return None
        extend_track_ids = extend_song_result.get("track_ids", []) or []
        if not extend_track_ids:
            print(f"No track_ids in extend response: {extend_song_result}")
            return None
        self.all_track_ids.extend(extend_track_ids)
        return self.process_songs(extend_track_ids, "extend_songs")

    def add_outro(self, prompt, seed=-1, audio_conditioning_path=None, audio_conditioning_song_id=None, custom_lyrics=None):
        outro_result = self.generate_outro(
            prompt, seed, audio_conditioning_path, audio_conditioning_song_id, custom_lyrics
        )
        if not outro_result:
            return None
        outro_track_ids = outro_result.get("track_ids", []) or []
        if not outro_track_ids:
            print(f"No track_ids in outro response: {outro_result}")
            return None
        self.all_track_ids.extend(outro_track_ids)
        return self.process_songs(outro_track_ids, "outro_songs")

    def generate_song(self, prompt, seed, custom_lyrics=None):
        url = f"{self.API_BASE_URL}/generate-proxy"
        headers = self.get_headers()
        data = {"prompt": prompt, "samplerOptions": {"seed": seed}}
        if custom_lyrics:
            data["lyricInput"] = custom_lyrics
        response = self.make_request(url, "POST", data, headers)
        if not response:
            return None
        try:
            return response.json()
        except ValueError as e:
            print(f"Failed to parse generate response as JSON: {e}. Body: {_safe_body_snippet(response)}")
            return None

    def generate_extend_song(self, prompt, seed, audio_conditioning_path, audio_conditioning_song_id, custom_lyrics=None):
        url = f"{self.API_BASE_URL}/generate-proxy"
        headers = self.get_headers()
        data = {
            "prompt": prompt,
            "samplerOptions": {
                "seed": seed,
                "audio_conditioning_path": audio_conditioning_path,
                "audio_conditioning_song_id": audio_conditioning_song_id,
                "audio_conditioning_type": "continuation",
            },
        }
        if custom_lyrics:
            data["lyricInput"] = custom_lyrics
        response = self.make_request(url, "POST", data, headers)
        if not response:
            return None
        try:
            return response.json()
        except ValueError as e:
            print(f"Failed to parse extend response as JSON: {e}. Body: {_safe_body_snippet(response)}")
            return None

    def generate_outro(self, prompt, seed, audio_conditioning_path, audio_conditioning_song_id, custom_lyrics=None):
        url = f"{self.API_BASE_URL}/generate-proxy"
        headers = self.get_headers()
        data = {
            "prompt": prompt,
            "samplerOptions": {
                "seed": seed,
                "audio_conditioning_path": audio_conditioning_path,
                "audio_conditioning_song_id": audio_conditioning_song_id,
                "audio_conditioning_type": "continuation",
                "crop_start_time": 0.9,
            },
        }
        if custom_lyrics:
            data["lyricInput"] = custom_lyrics
        response = self.make_request(url, "POST", data, headers)
        if not response:
            return None
        try:
            return response.json()
        except ValueError as e:
            print(f"Failed to parse outro response as JSON: {e}. Body: {_safe_body_snippet(response)}")
            return None

    def process_songs(self, track_ids, folder, max_attempts=72, poll_interval=5):
        """Process generated songs, wait until ready, and download them."""
        if not track_ids:
            print(f"No track_ids to process for {folder}.")
            return None
        print(f"Processing songs in {folder} with track_ids {track_ids}...")
        attempts = 0
        while True:
            attempts += 1
            status_result = self.check_song_status(track_ids)
            if status_result is None:
                print(f"Error checking song status for {folder}.")
                return None
            if status_result.get("all_finished", False):
                songs = []
                for song in status_result["data"].get("songs", []):
                    if song.get("error_type") == "MODERATION":
                        print(f"Song '{song.get('title', '?')}' was moderated; skipping download.")
                        songs.append(song)
                        continue
                    song_path = song.get("song_path")
                    title = song.get("title") or song.get("id") or "song"
                    if not song_path:
                        print(f"Song '{title}' has no song_path; skipping download.")
                        songs.append(song)
                        continue
                    self.download_song(song_path, title, folder=folder)
                    songs.append(song)
                print(f"All songs in {folder} are ready and downloaded.")
                return songs
            if attempts >= max_attempts:
                print(
                    f"Timed out waiting for songs in {folder} after "
                    f"{attempts * poll_interval}s. Track IDs kept in "
                    "`all_track_ids`; try check_song_status() later."
                )
                return None
            time.sleep(poll_interval)

    def check_song_status(self, song_ids):
        if not song_ids:
            print("check_song_status called with empty song_ids.")
            return None
        url = f"{self.API_BASE_URL}/songs?songIds={','.join(song_ids)}"
        headers = self.get_headers(True)
        response = self.make_request(url, "GET", None, headers)
        if response:
            try:
                data = response.json()
            except ValueError as e:
                print(f"Failed to parse song-status response as JSON: {e}. Body: {_safe_body_snippet(response)}")
                return None
            songs = data.get("songs", []) if isinstance(data, dict) else []
            all_finished = bool(songs) and all(song.get("finished") for song in songs)
            return {"all_finished": all_finished, "data": data}
        else:
            return None

    def download_song(self, song_url, song_title, folder="downloaded_songs"):
        if not song_url:
            print(f"Cannot download '{song_title}': empty URL.")
            return None
        os.makedirs(folder, exist_ok=True)
        safe_title = _sanitize_filename(song_title)
        file_path = os.path.join(folder, f"{safe_title}.mp3")
        try:
            response = requests.get(song_url, timeout=self.request_timeout)
            response.raise_for_status()
            with open(file_path, "wb") as file:
                file.write(response.content)
            print(f"Downloaded {song_title} with url {song_url} to {file_path}")
            return file_path
        except requests.exceptions.RequestException as e:
            print(f"Failed to download the song. Error: {e}")
            return None


def _safe_body_snippet(response, limit=500):
    try:
        text = response.text or ""
    except Exception:
        return "<unreadable body>"
    text = text.strip()
    if len(text) > limit:
        return text[:limit] + "...(truncated)"
    return text or "<empty body>"


def _parse_retry_after(response):
    try:
        value = response.headers.get("Retry-After")
    except Exception:
        return None
    if value is None:
        return None
    try:
        return max(1, min(120, int(str(value).strip())))
    except (ValueError, TypeError):
        return None
