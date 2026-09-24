#!/usr/bin/env python
"""Container health probe: exits 0 only when the service answers healthy."""

import json
import os
import sys
import urllib.request

port = os.environ.get("PORT", "8080")
try:
    with urllib.request.urlopen(
        f"http://127.0.0.1:{port}/healthz", timeout=3
    ) as resp:
        payload = json.load(resp)
    if resp.status == 200 and payload.get("status") == "ok":
        sys.exit(0)
except Exception:
    pass
sys.exit(1)
