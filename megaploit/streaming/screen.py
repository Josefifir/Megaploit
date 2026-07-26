"""
megaploit.streaming.screen
~~~~~~~~~~~~~~~~~~~~~~~~~~
Screen-capture Camera: grabs the primary display in a background daemon
thread and JPEG-encodes each frame.  Used by the desktop Flask app.
"""

from __future__ import annotations

import threading
import time

import cv2
import mss
import numpy

try:
    import pyautogui as _pag
    _HAS_PYAUTOGUI = True
except ImportError:
    _HAS_PYAUTOGUI = False


class Camera:
    """
    Singleton-style screen grabber.
    Multiple Camera() instances share the same background thread.
    The thread stops automatically after 10 s of inactivity.
    """

    _lock = threading.Lock()
    _thread: threading.Thread | None = None
    _frame: bytes | None = None
    _last_access: float = 0.0

    def __init__(self) -> None:
        with Camera._lock:
            if Camera._thread is None or not Camera._thread.is_alive():
                Camera._last_access = time.time()
                Camera._frame = None
                Camera._thread = threading.Thread(
                    target=Camera._capture_loop, daemon=True
                )
                Camera._thread.start()

        # Wait up to 5 s for first frame
        deadline = time.time() + 5
        while Camera._frame is None and time.time() < deadline:
            time.sleep(0.05)

    def get_frame(self) -> bytes | None:
        Camera._last_access = time.time()
        return Camera._frame

    @staticmethod
    def _capture_loop() -> None:
        if _HAS_PYAUTOGUI:
            w, h = _pag.size()
        else:
            w, h = 1920, 1080
        monitor = {"top": 0, "left": 0, "width": w, "height": h}

        with mss.mss() as sct:
            while True:
                if time.time() - Camera._last_access > 10:
                    break
                raw = sct.grab(monitor)
                arr = numpy.array(raw)
                bgr = cv2.cvtColor(arr, cv2.COLOR_BGRA2BGR)
                ok, buf = cv2.imencode(".jpg", bgr, [cv2.IMWRITE_JPEG_QUALITY, 70])
                if ok:
                    Camera._frame = buf.tobytes()
                time.sleep(0.033)   # ≈30 fps

        with Camera._lock:
            Camera._thread = None
