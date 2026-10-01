"""Tests for udio_wrapper.hcaptcha_solver (issue #7)."""

import os
import unittest
from unittest.mock import MagicMock, patch

from udio_wrapper.hcaptcha_solver import (
    HCaptchaSolver,
    UDIO_HCAPTCHA_SITEKEY,
    is_hcaptcha_blocked,
    is_retryable_status,
)


def _fake_response(status_code=200, text="", json_data=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    if json_data is not None:
        resp.json.return_value = json_data
    return resp


class TestIsHcaptchaBlocked(unittest.TestCase):
    def test_none_is_not_blocked(self):
        self.assertFalse(is_hcaptcha_blocked(None))

    def test_500_is_blocked(self):
        self.assertTrue(is_hcaptcha_blocked(_fake_response(500, "Internal Server Error")))

    def test_403_is_blocked(self):
        self.assertTrue(is_hcaptcha_blocked(_fake_response(403, "Forbidden")))

    def test_503_is_blocked(self):
        self.assertTrue(is_hcaptcha_blocked(_fake_response(503, "")))

    def test_captcha_keyword_is_blocked(self):
        self.assertTrue(is_hcaptcha_blocked(_fake_response(200, '{"error": "captcha required"}')))

    def test_clean_200_is_not_blocked(self):
        self.assertFalse(is_hcaptcha_blocked(_fake_response(200, '{"track_ids": ["a", "b"]}')))

    def test_retryable_statuses(self):
        for code in (429, 500, 502, 503, 504):
            self.assertTrue(is_retryable_status(code), code)
        for code in (200, 400, 401, 404):
            self.assertFalse(is_retryable_status(code), code)


class TestHCaptchaSolverConfig(unittest.TestCase):
    def test_default_sitekey(self):
        solver = HCaptchaSolver()
        self.assertEqual(solver.sitekey, UDIO_HCAPTCHA_SITEKEY)
        self.assertEqual(solver.site_url, "https://www.udio.com")

    def test_env_resolution_2captcha(self):
        with patch.dict(os.environ, {"CAPTCHA_API_KEY": "key123"}, clear=False):
            # Ensure other keys don't interfere.
            os.environ.pop("CAPSOLVER_API_KEY", None)
            os.environ.pop("NOPECHA_API_KEY", None)
            solver = HCaptchaSolver()
            self.assertEqual(solver.api_key, "key123")
            self.assertEqual(solver.service, "2captcha")

    def test_env_resolution_capsolver(self):
        with patch.dict(os.environ, {"CAPSOLVER_API_KEY": "cap123"}, clear=False):
            os.environ.pop("CAPTCHA_API_KEY", None)
            os.environ.pop("TWOCAPTCHA_API_KEY", None)
            os.environ.pop("TWO_CAPTCHA_API_KEY", None)
            os.environ.pop("NOPECHA_API_KEY", None)
            solver = HCaptchaSolver()
            self.assertEqual(solver.api_key, "cap123")
            self.assertEqual(solver.service, "capsolver")

    def test_env_resolution_nopecha(self):
        with patch.dict(os.environ, {"NOPECHA_API_KEY": "nope123"}, clear=False):
            os.environ.pop("CAPTCHA_API_KEY", None)
            os.environ.pop("TWOCAPTCHA_API_KEY", None)
            os.environ.pop("TWO_CAPTCHA_API_KEY", None)
            os.environ.pop("CAPSOLVER_API_KEY", None)
            solver = HCaptchaSolver()
            self.assertEqual(solver.api_key, "nope123")
            self.assertEqual(solver.service, "nopecha")

    def test_no_key_returns_none_with_hint(self):
        with patch.dict(os.environ, {}, clear=True):
            solver = HCaptchaSolver()
            self.assertIsNone(solver.get_token())

    def test_custom_callback_takes_precedence(self):
        solver = HCaptchaSolver(solver_callback=lambda sk, url: "callback-token")
        self.assertEqual(solver.get_token(), "callback-token")

    def test_custom_callback_error_returns_none(self):
        def boom(sk, url):
            raise RuntimeError("boom")

        solver = HCaptchaSolver(solver_callback=boom)
        self.assertIsNone(solver.get_token())

    def test_cache_and_force(self):
        calls = []

        def cb(sk, url):
            calls.append(1)
            return f"token-{len(calls)}"

        solver = HCaptchaSolver(solver_callback=cb)
        self.assertEqual(solver.get_token(), "token-1")
        # Cached.
        self.assertEqual(solver.get_token(), "token-1")
        self.assertEqual(len(calls), 1)
        # Forced refresh.
        self.assertEqual(solver.get_token(force=True), "token-2")
        solver.clear_cache()
        self.assertEqual(solver.get_token(), "token-3")


class TestSolverServices(unittest.TestCase):
    @patch("udio_wrapper.hcaptcha_solver.time.sleep", return_value=None)
    @patch("udio_wrapper.hcaptcha_solver.requests.get")
    @patch("udio_wrapper.hcaptcha_solver.requests.post")
    def test_2captcha_json_api(self, mock_post, mock_get, _sleep):
        mock_post.return_value.json.return_value = {"status": 1, "request": "task1"}
        not_ready = MagicMock()
        not_ready.json.return_value = {"status": 0, "request": "CAPCHA_NOT_READY"}
        ready = MagicMock()
        ready.json.return_value = {"status": 1, "request": "solved-token"}
        mock_get.side_effect = [not_ready, ready]

        solver = HCaptchaSolver(api_key="k", service="2captcha", poll_interval=0)
        self.assertEqual(solver.get_token(), "solved-token")

    @patch("udio_wrapper.hcaptcha_solver.time.sleep", return_value=None)
    @patch("udio_wrapper.hcaptcha_solver.requests.post")
    def test_capsolver(self, mock_post, _sleep):
        create = MagicMock()
        create.json.return_value = {"errorId": 0, "taskId": "t1"}
        processing = MagicMock()
        processing.json.return_value = {"errorId": 0, "status": "processing"}
        ready = MagicMock()
        ready.json.return_value = {
            "errorId": 0,
            "status": "ready",
            "solution": {"gRecaptchaResponse": "cap-token"},
        }
        mock_post.side_effect = [create, processing, ready]

        solver = HCaptchaSolver(api_key="k", service="capsolver", poll_interval=0)
        self.assertEqual(solver.get_token(), "cap-token")

    @patch("udio_wrapper.hcaptcha_solver.time.sleep", return_value=None)
    @patch("udio_wrapper.hcaptcha_solver.requests.get")
    @patch("udio_wrapper.hcaptcha_solver.requests.post")
    def test_nopecha(self, mock_post, mock_get, _sleep):
        submit = MagicMock()
        submit.json.return_value = {"data": "job1"}
        mock_post.return_value = submit
        pending = MagicMock()
        pending.json.return_value = {"error": 14, "message": "Incomplete job"}
        done = MagicMock()
        done.json.return_value = {"data": "nope-token"}
        mock_get.side_effect = [pending, done]

        solver = HCaptchaSolver(api_key="k", service="nopecha", poll_interval=0)
        self.assertEqual(solver.get_token(), "nope-token")


if __name__ == "__main__":
    unittest.main()
