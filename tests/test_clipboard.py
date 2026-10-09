"""Clipboard tests.

The helpers are mocked: a real clipboard needs a display server, and CI has
none. What matters here is that the right command is chosen and invoked in
a way that does not hang.
"""

import subprocess

from franking import clipboard


class TestHelperSelection:
    def test_prefers_the_first_available_helper(self, monkeypatch):
        monkeypatch.setattr(clipboard.shutil, "which",
                            lambda n: "/usr/bin/xclip" if n == "xclip" else None)
        assert clipboard.available_helper() == "xclip"

    def test_reports_none_when_nothing_is_installed(self, monkeypatch):
        monkeypatch.setattr(clipboard.shutil, "which", lambda n: None)
        assert clipboard.available_helper() is None


class TestCopy:
    def test_empty_text_is_refused(self):
        ok, why = clipboard.copy("")
        assert ok is False
        assert "nothing" in why

    def test_uses_the_helper_and_names_it(self, monkeypatch):
        calls = []
        monkeypatch.setattr(clipboard.shutil, "which",
                            lambda n: "/usr/bin/wl-copy" if n == "wl-copy" else None)
        monkeypatch.setattr(clipboard.subprocess, "run",
                            lambda *a, **k: calls.append((a, k)))
        ok, how = clipboard.copy("hello")
        assert (ok, how) == (True, "wl-copy")
        assert calls[0][0][0] == ["wl-copy"]

    def test_never_captures_output(self, monkeypatch):
        """Regression: capture_output hangs wl-copy until the timeout.

        wl-copy forks a server to hold the selection and that child
        inherits the pipes, so capturing waits for an EOF that only
        arrives when the selection is given up.
        """
        seen = {}
        monkeypatch.setattr(clipboard.shutil, "which",
                            lambda n: "/usr/bin/wl-copy" if n == "wl-copy" else None)
        monkeypatch.setattr(clipboard.subprocess, "run",
                            lambda *a, **k: seen.update(k))
        clipboard.copy("hello")
        assert seen.get("capture_output") is not True
        assert seen["stdout"] is subprocess.DEVNULL
        assert seen["stderr"] is subprocess.DEVNULL
        assert seen["start_new_session"] is True

    def test_falls_through_to_the_next_helper_on_failure(self, monkeypatch):
        monkeypatch.setattr(clipboard.shutil, "which", lambda n: f"/usr/bin/{n}")

        def flaky(command, **kwargs):
            if command[0] == "wl-copy":
                raise subprocess.TimeoutExpired(command, 5)
            return None

        monkeypatch.setattr(clipboard.subprocess, "run", flaky)
        ok, how = clipboard.copy("hello")
        assert ok is True
        assert how == "xclip"

    def test_osc52_fallback_when_no_helper_exists(self, monkeypatch):
        written = []
        monkeypatch.setattr(clipboard.shutil, "which", lambda n: None)
        monkeypatch.setenv("TERM", "xterm-256color")
        monkeypatch.setattr(clipboard.sys.stdout, "write", written.append)
        monkeypatch.setattr(clipboard.sys.stdout, "flush", lambda: None)
        ok, how = clipboard.copy("hello")
        assert (ok, how) == (True, "OSC 52")
        assert written[0].startswith("\033]52;c;")

    def test_osc52_can_be_refused(self, monkeypatch):
        """A running TUI owns stdout, so the escape must not be written."""
        monkeypatch.setattr(clipboard.shutil, "which", lambda n: None)
        monkeypatch.setenv("TERM", "xterm-256color")
        monkeypatch.setattr(
            clipboard.sys.stdout, "write",
            lambda *a: pytest_fail("stdout written with osc52=False"),
        )
        ok, how = clipboard.copy("hello", osc52=False)
        assert ok is False
        assert "no clipboard helper" in how


def pytest_fail(message):
    raise AssertionError(message)
