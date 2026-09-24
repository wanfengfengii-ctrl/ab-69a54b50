"""End-to-end HTTP tests against the stdlib server (real socket, no network)."""

import json
import random
import socket
import threading
import unittest
import urllib.request
import urllib.error

from app import gf
from app.server import create_server


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_shares(cards, threshold, key_bytes, rng):
    shares = [bytearray() for _ in cards]
    for secret in key_bytes:
        coeffs = [secret] + [rng.randrange(256) for _ in range(threshold - 1)]
        for i, x in enumerate(cards):
            shares[i].append(gf.poly_eval(coeffs, x))
    return [s.hex() for s in shares]


class ServerTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.server = create_server(cls.port)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def post_json(self, payload, raw=None, content_type="application/json"):
        data = raw if raw is not None else json.dumps(payload).encode()
        req = urllib.request.Request(
            self.base + "/api/recovery/reconstruct",
            data=data,
            headers={"Content-Type": content_type},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=5) as resp:
            return resp.status, resp.read(), resp.headers


class HttpEndpointTests(ServerTestBase):
    def test_healthz(self):
        status, body, _ = self.get("/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "ok")

    def test_index_page_served(self):
        status, body, headers = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn("/api/recovery/reconstruct".encode(), body)

    def test_unknown_route_404(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.get("/nope")
        self.assertEqual(cm.exception.code, 404)

    def test_consistent_flow(self):
        rng = random.Random(900)
        cards = [1, 2, 3, 4, 5]
        key = bytes(range(8))
        shares = make_shares(cards, 3, key, rng)
        status, data = self.post_json(
            {"cards": cards, "threshold": 3, "shares": shares}
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "CONSISTENT")
        self.assertEqual(data["key"], key.hex())
        self.assertNotIn("bad_card", data)

    def test_recovered_flow_names_bad_card(self):
        rng = random.Random(901)
        cards = [10, 20, 30, 40, 50, 60]
        shares = make_shares(cards, 3, b"keykey", rng)
        shares[2] = "ff" * len(b"keykey")
        status, data = self.post_json(
            {"cards": cards, "threshold": 3, "shares": shares}
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "RECOVERED")
        self.assertEqual(data["bad_card"], 30)
        self.assertEqual(data["key"], b"keykey".hex())

    def test_conflict_does_not_leak_key(self):
        rng = random.Random(902)
        cards = [1, 2, 3, 4, 5, 6]
        shares = make_shares(cards, 3, b"secret", rng)
        shares[0] = "00" * len(b"secret")
        shares[4] = "ff" * len(b"secret")
        status, data = self.post_json(
            {"cards": cards, "threshold": 3, "shares": shares}
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "CONFLICT")
        self.assertNotIn("key", data)
        self.assertNotIn("bad_card", data)
        serialized = json.dumps(data)
        self.assertNotIn(b"secret".hex(), serialized)

    def test_duplicate_card_returns_locatable_400(self):
        status, data = self.post_json(
            {"cards": [1, 2, 2, 4], "threshold": 2, "shares": ["ab"] * 4}
        )
        self.assertEqual(status, 400)
        self.assertFalse(data["ok"])
        errs = data["errors"]
        self.assertTrue(any(
            e["field"] == "card" and e.get("index") == 2 for e in errs
        ))

    def test_non_hex_share_returns_locatable_400(self):
        status, data = self.post_json(
            {"cards": [1, 2, 3, 4], "threshold": 2,
             "shares": ["ab", "zz", "ab", "abc"]}
        )
        self.assertEqual(status, 400)
        indexes = {e.get("index") for e in data["errors"] if e["field"] == "share"}
        self.assertEqual(indexes, {1, 3})

    def test_unequal_length_returns_locatable_400(self):
        status, data = self.post_json(
            {"cards": [1, 2, 3, 4], "threshold": 2,
             "shares": ["aabb", "aabb", "aabb", "aa"]}
        )
        self.assertEqual(status, 400)
        self.assertTrue(any(
            e["field"] == "share" and e.get("index") == 3 for e in data["errors"]
        ))

    def test_threshold_out_of_range_400(self):
        status, data = self.post_json(
            {"cards": [1, 2, 3, 4], "threshold": 9, "shares": ["ab"] * 4}
        )
        self.assertEqual(status, 400)
        self.assertTrue(any(e["field"] == "threshold" for e in data["errors"]))

    def test_malformed_json_400(self):
        status, data = self.post_json(None, raw=b"{not json", )
        self.assertEqual(status, 400)
        self.assertFalse(data["ok"])

    def test_empty_body_400(self):
        status, data = self.post_json(None, raw=b"")
        self.assertEqual(status, 400)

    def test_new_submission_replaces_old_conclusion_at_api_level(self):
        # The API is stateless; this documents that no conclusion is retained
        # server-side between requests (the page clears on submit too).
        rng = random.Random(903)
        cards = [1, 2, 3, 4, 5, 6]
        bad = make_shares(cards, 3, b"secret", rng)
        bad[0] = "00" * 6
        bad[4] = "ff" * 6
        s1, d1 = self.post_json({"cards": cards, "threshold": 3, "shares": bad})
        self.assertEqual(d1["status"], "CONFLICT")

        good = make_shares(cards, 3, b"secret", rng)
        s2, d2 = self.post_json({"cards": cards, "threshold": 3, "shares": good})
        self.assertEqual(s2, 200)
        self.assertEqual(d2["status"], "CONSISTENT")
        self.assertEqual(d2["key"], b"secret".hex())


if __name__ == "__main__":
    unittest.main()
