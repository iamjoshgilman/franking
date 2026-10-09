"""Copy text to the system clipboard.

Tries the native helper for the session type first and falls back to the
terminal's own OSC 52 escape, which works over SSH where no helper exists.
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import sys

# Ordered by preference; the first available binary wins.
HELPERS: tuple[tuple[str, list[str]], ...] = (
    ("wl-copy", ["wl-copy"]),
    ("xclip", ["xclip", "-selection", "clipboard"]),
    ("xsel", ["xsel", "--clipboard", "--input"]),
    ("pbcopy", ["pbcopy"]),
    ("clip.exe", ["clip.exe"]),
)


def available_helper() -> str | None:
    for name, _ in HELPERS:
        if shutil.which(name):
            return name
    return None


def _osc52(text: str) -> bool:
    """Ask the terminal emulator to set the clipboard."""
    try:
        encoded = base64.b64encode(text.encode()).decode()
        sys.stdout.write(f"\033]52;c;{encoded}\a")
        sys.stdout.flush()
        return True
    except OSError:
        return False


def copy(text: str, osc52: bool = True) -> tuple[bool, str]:
    """Copy ``text``. Returns (success, description of the method used).

    Pass ``osc52=False`` when something else owns the terminal -- a running
    TUI -- so the escape sequence is never written into its output. The
    caller then supplies its own fallback.
    """
    if not text:
        return False, "nothing to copy"

    for name, command in HELPERS:
        if not shutil.which(name):
            continue
        try:
            subprocess.run(
                command,
                input=text.encode(),
                check=True,
                # Deliberately NOT capture_output: wl-copy forks a server to
                # hold the selection, and that child inherits the pipes, so
                # capturing blocks until the timeout and a copy that
                # actually worked is reported as a failure.
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                # Keep that server alive after this process exits.
                start_new_session=(name == "wl-copy"),
            )
            return True, name
        except (subprocess.SubprocessError, OSError):
            continue

    if osc52 and os.environ.get("TERM") and _osc52(text):
        return True, "OSC 52"
    return False, "no clipboard helper found"
