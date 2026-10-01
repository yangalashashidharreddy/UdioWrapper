"""Tests for UdioWrapper hCaptcha retry logic (issue #7)."""

import unittest
from unittest.mock import MagicMock, patch

import requests

from udio_wrapper import UdioWrapper


def _resp(status_code=200, text="", json_data=None, headers=None):
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    r.headers = headers or {}
    if json_data is not None:
        r.json.return_value = json_data
    else:
        r.json.return_value = {}
    if 200 <= status_code < 400:
        r.raise_for_status.return_value = None
    else:
        r.raise_for_status.side_effect = requests.exceptions.HTTPError(
            f"{status_code} Error: {text[:50]}"
        )
    return r


class TestMakeRequestCaptchaRetry(unittest.TestCase):
    @patch("udio_wrapper.time.sleep", return_value=None)
    @patch("udio_wrapper.requests.post")
    def test_500_triggers_solve_and_retry_with_token(self, mock_post, _sleep):
        blocked = _resp(500, "Internal Server Error")
        ok = _resp(200, '{"track_ids": ["a"]}', {"track_ids": ["a"]})
        mock_post.side_effect = [blocked, ok]

        wrapper = UdioWrapper(
            "auth", solver_callback=lambda sk, url: "fresh-token", max_retries=2
        )
        result = wrapper.make_request("https://www.udio.com/api/generate-proxy", "POST", {"prompt": "x"}, {"Cookie": "c"})

        self.assertIsNotNone(result)
        self.assertEqual(result.json(), {"track_ids": ["a"]})
        self.assertEqual(mock_post.call_count, 2)
        # Second call must carry the token in header + payload.
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["headers"].get("h-captcha-response"), "fresh-token")
        self.assertEqual(kwargs["json"].get("captchaToken"), "fresh-token")

    @patch("udio_wrapper.time.sleep", return_value=None)
    @patch("udio_wrapper.requests.post")
    def test_first_attempt_has_no_token_lazy_solving(self, mock_post, _sleep):
        ok = _resp(200, "{}", {"track_ids": []})
        mock_post.return_value = ok
        solver = MagicMock()
        solver.get_token.return_value = "should-not-be-used"

        wrapper = UdioWrapper("auth", max_retries=2)
        wrapper._captcha_solver = solver
        wrapper.make_request("https://www.udio.com/api/generate-proxy", "POST", {"prompt": "x"}, {})

        # Lazy: solver not consulted when first attempt succeeds.
        solver.get_token.assert_not_called()

    @patch("udio_wrapper.time.sleep", return_value=None)
    @patch("udio_wrapper.requests.post")
    def test_no_solver_still_retries_and_returns_none(self, mock_post, _sleep):
        mock_post.return_value = _resp(500, "Internal Server Error")
        wrapper = UdioWrapper("auth", max_retries=1)
        # Ensure no API key configured.
        wrapper._captcha_solver.api_key = None
        wrapper._captcha_solver.solver_callback = None
        result = wrapper.make_request("https://x/api", "POST", {}, {})
        self.assertIsNone(result)
        self.assertEqual(mock_post.call_count, 2)

    @patch("udio_wrapper.time.sleep", return_value=None)
    @patch("udio_wrapper.requests.post")
    def test_401_fails_fast_without_retry(self, mock_post, _sleep):
        mock_post.return_value = _resp(401, "Unauthorized")
        wrapper = UdioWrapper("auth", solver_callback=lambda sk, url: "tok", max_retries=3)
        result = wrapper.make_request("https://x/api", "POST", {}, {})
        self.assertIsNone(result)
        self.assertEqual(mock_post.call_count, 1)

    @patch("udio_wrapper.time.sleep", return_value=None)
    @patch("udio_wrapper.requests.post")
    def test_manual_token_used_from_first_attempt(self, mock_post, _sleep):
        ok = _resp(200, "{}", {})
        mock_post.return_value = ok
        wrapper = UdioWrapper("auth", captcha_token="manual-123", max_retries=1)
        wrapper.make_request("https://x/api", "POST", {"prompt": "x"}, {})
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["headers"].get("h-captcha-response"), "manual-123")
        self.assertEqual(kwargs["json"].get("captchaToken"), "manual-123")

    @patch("udio_wrapper.time.sleep", return_value=None)
    @patch("udio_wrapper.requests.get")
    def test_429_retries_with_backoff(self, mock_get, mock_sleep):
        mock_get.side_effect = [_resp(429, "Too Many Requests"), _resp(200, "{}", {})]
        wrapper = UdioWrapper("auth", max_retries=2)
        result = wrapper.make_request("https://x/api/songs?songIds=a", "GET", None, {})
        self.assertIsNotNone(result)
        self.assertEqual(mock_get.call_count, 2)
        mock_sleep.assert_called()

    @patch("udio_wrapper.requests.post")
    def test_network_error_retries_then_none(self, mock_post):
        mock_post.side_effect = requests.exceptions.ConnectionError("down")
        wrapper = UdioWrapper("auth", max_retries=1)
        with patch("udio_wrapper.time.sleep", return_value=None):
            result = wrapper.make_request("https://x/api", "POST", {}, {})
        self.assertIsNone(result)
        self.assertEqual(mock_post.call_count, 2)


class TestGenerateAndStatus(unittest.TestCase):
    def test_generate_song_parses_json(self):
        wrapper = UdioWrapper("auth")
        fake = _resp(200, "{}", {"track_ids": ["a", "b"]})
        with patch.object(wrapper, "make_request", return_value=fake):
            self.assertEqual(wrapper.generate_song("p", -1), {"track_ids": ["a", "b"]})

    def test_generate_song_bad_json_returns_none(self):
        wrapper = UdioWrapper("auth")
        bad = _resp(200, "not json")
        bad.json.side_effect = ValueError("bad")
        with patch.object(wrapper, "make_request", return_value=bad):
            self.assertIsNone(wrapper.generate_song("p", -1))

    def test_check_song_status_empty_ids(self):
        wrapper = UdioWrapper("auth")
        self.assertIsNone(wrapper.check_song_status([]))

    def test_check_song_status_all_finished(self):
        wrapper = UdioWrapper("auth")
        fake = _resp(200, "{}", {"songs": [{"finished": True}, {"finished": True}]})
        with patch.object(wrapper, "make_request", return_value=fake):
            res = wrapper.check_song_status(["a", "b"])
            self.assertTrue(res["all_finished"])

    def test_create_song_no_track_ids(self):
        wrapper = UdioWrapper("auth")
        with patch.object(wrapper, "generate_song", return_value={"track_ids": []}):
            self.assertIsNone(wrapper.create_song("p"))

    def test_process_songs_timeout(self):
        wrapper = UdioWrapper("auth")
        pending = {"all_finished": False, "data": {"songs": [{"finished": False}]}}
        with patch.object(wrapper, "check_song_status", return_value=pending):
            with patch("udio_wrapper.time.sleep", return_value=None):
                self.assertIsNone(wrapper.process_songs(["a"], "f", max_attempts=2, poll_interval=0))

    def test_download_song_sanitizes_filename(self):
        wrapper = UdioWrapper("auth")
        fake = _resp(200, "binary")
        fake.content = b"MP3DATA"
        with patch("udio_wrapper.requests.get", return_value=fake):
            with patch("udio_wrapper.os.makedirs"):
                m_open = MagicMock()
                with patch("builtins.open", m_open):
                    path = wrapper.download_song("https://x/s.mp3", 'a/b:c*d?"<>|', folder="f")
                    self.assertIn("f", path)
                    self.assertNotIn("/", path.split("f", 1)[1][1:])


if __name__ == "__main__":
    unittest.main()
