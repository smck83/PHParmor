"""Sends the synthetic benign requests with Python requests."""
import os

import requests

BASE = os.environ["BASE"]
DATA = bytes((i * 31 + 7) % 256 for i in range(4096))


def post(name, **kw):
    r = requests.post(f"{BASE}/?corpus={name}", timeout=30, **kw)
    print(name, r.status_code, r.text.strip())


post("python-fields", files=[
    ("name", (None, "Alice Example")),
    ("tags[]", (None, "one")),
    ("tags[]", (None, "two")),
    ("addr[home][city]", (None, "Springfield")),
    ("unicode", (None, "héllo ✓")),
    ("empty", (None, "")),
])
post("python-files", data={"title": "report"}, files=[
    ("doc", ("data.bin", DATA, "application/octet-stream")),
    ("empty", ("empty.txt", b"")),
    ("photos[]", ("résumé ✓.png", b"fake png", "image/png")),
])
post("python-urlencoded", data={"q": "search terms & more", "a[]": "1"})
