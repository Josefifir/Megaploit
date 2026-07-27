"""
megaploit.streaming.screen
~~~~~~~~~~~~~~~~~~~~~~~~~~
Screen-capture Camera: grabs the primary display in a background daemon
thread and JPEG-encodes each frame.  Used by the desktop Flask app.

Optimisations
-------------
- Target FPS is configurable (default 20); the loop uses time.monotonic()
  for precise pacing so frame rate stays accurate on loaded machines.
- Output is downscaled to a configurable width (default 1280 px) before
  JPEG encoding — this is the single biggest bandwidth/CPU saving because
  the JPEG encoder work scales with pixel count, not content complexity.
- JPEG quality is adaptive: if the last encode took longer than one frame
  budget, quality is stepped down (min 40); if encode is fast, it steps
  back up (max 85).  This keeps frame rate stable under load.
- The frame buffer is a single shared bytes object guarded by a lock —
  consumers always get the latest frame without any queue overhead.
"""

from __future__ import annotations

import threading
import time
from typing import ClassVar

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

    Parameters (class-level, set before first instantiation):
        target_fps   — desired capture rate (default 20)
        scale_width  — output frame width in pixels (default 1280)
    """

    target_fps:  ClassVar[int] = 20
    scale_width: ClassVar[int] = 1280

    _lock:        ClassVar[threading.Lock]          = threading.Lock()
    _frame_lock:  ClassVar[threading.Lock]          = threading.Lock()
    _thread:      ClassVar[threading.Thread | None] = None
    _frame:       ClassVar[bytes | None]            = None
    _last_access: ClassVar[float]                   = 0.0

    def __init__(self) -> None:
        with Camera._lock:
            if Camera._thread is None or not Camera._thread.is_alive():
                Camera._last_access = time.monotonic()
                with Camera._frame_lock:
                    Camera._frame = None
                Camera._thread = threading.Thread(
                    target=Camera._capture_loop, daemon=True
                )
                Camera._thread.start()

        # Wait up to 5 s for first frame
        deadline = time.monotonic() + 5
        while Camera._frame is None and time.monotonic() < deadline:
            time.sleep(0.02)

    def get_frame(self) -> bytes | None:
        Camera._last_access = time.monotonic()
        with Camera._frame_lock:
            return Camera._frame

    @staticmethod
    def _capture_loop() -> None:
        fps         = Camera.target_fps
        scale_width = Camera.scale_width
        tick        = 1.0 / fps
        quality     = 75          # start mid-range; adaptive below
        min_quality = 40
        max_quality = 85
        quality_step = 5

        # Determine source dimensions once
        if _HAS_PYAUTOGUI:
            src_w, src_h = _pag.size()
        else:
            src_w, src_h = 1920, 1080

        scale_h = int(src_h * scale_width / src_w)
        # Ensure even dimensions
        out_w = scale_width + (scale_width % 2)
        out_h = scale_h     + (scale_h % 2)
        needs_resize = (src_w != out_w) or (src_h != out_h)

        monitor = {"top": 0, "left": 0, "width": src_w, "height": src_h}
        encode_params = [cv2.IMWRITE_JPEG_QUALITY, quality]

        with mss.mss() as sct:
            deadline = time.monotonic() + tick
            while True:
                # Stop if no consumer has asked for a frame in 10 s
                if time.monotonic() - Camera._last_access > 10:
                    break

                t0 = time.monotonic()

                raw = sct.grab(monitor)
                arr = numpy.array(raw)
                bgr = cv2.cvtColor(arr, cv2.COLOR_BGRA2BGR)
                if needs_resize:
                    bgr = cv2.resize(bgr, (out_w, out_h),
                                     interpolation=cv2.INTER_LINEAR)

                encode_params[1] = quality
                ok, buf = cv2.imencode(".jpg", bgr, encode_params)
                if ok:
                    with Camera._frame_lock:
                        Camera._frame = buf.tobytes()

                encode_ms = (time.monotonic() - t0) * 1000

                # Adaptive quality: back off if encode is eating into frame budget
                if encode_ms > tick * 1000 * 0.6:
                    quality = max(min_quality, quality - quality_step)
                elif encode_ms < tick * 1000 * 0.3 and quality < max_quality:
                    quality = min(max_quality, quality + quality_step)

                # Precise sleep for the remainder of this tick
                now  = time.monotonic()
                wait = deadline - now
                if wait > 0:
                    time.sleep(wait)
                deadline += tick   # advance even on overrun

        with Camera._lock:
            Camera._thread = None
