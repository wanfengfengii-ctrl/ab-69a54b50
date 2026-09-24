"""Tests for validation and GF(256) Shamir reconstruction semantics."""

import random
import unittest

from app import gf
from app.reconstruct import (
    MAX_CARDS,
    MIN_CARDS,
    Status,
    analyze,
    reconstruct,
    validate_payload,
)


def make_shares(cards, threshold, key_bytes, rng):
    """Generate honest Shamir shares: one random polynomial per key byte."""
    shares = [bytearray() for _ in cards]
    for secret in key_bytes:
        coeffs = [secret] + [rng.randrange(256) for _ in range(threshold - 1)]
        for i, x in enumerate(cards):
            shares[i].append(gf.poly_eval(coeffs, x))
    return [s.hex() for s in shares]


def payload(cards, threshold, shares):
    return {"cards": cards, "threshold": threshold, "shares": shares}


def corrupt(share_hex, rng, n_bytes=2):
    """Flip at least one byte to a different value at random positions."""
    raw = bytearray.fromhex(share_hex)
    for pos in rng.sample(range(len(raw)), min(n_bytes, len(raw))):
        raw[pos] ^= rng.randrange(1, 256)
    return raw.hex()


class ConsistentTests(unittest.TestCase):
    def test_all_honest_shares_recover_key(self):
        rng = random.Random(101)
        key = bytes(range(16))
        for n, k in ((4, 2), (4, 3), (5, 3), (6, 4), (8, 5), (8, 2)):
            cards = list(range(10, 10 + n))
            shares = make_shares(cards, k, key, rng)
            v, r = analyze(payload(cards, k, shares))
            self.assertTrue(v.ok, v.errors)
            self.assertIs(r.status, Status.CONSISTENT)
            self.assertEqual(r.key_hex, key.hex())
            self.assertIsNone(r.bad_card)

    def test_single_byte_key(self):
        rng = random.Random(102)
        cards = [1, 2, 3, 4, 5]
        shares = make_shares(cards, 3, b"\xa3", rng)
        v, r = analyze(payload(cards, 3, shares))
        self.assertTrue(v.ok)
        self.assertEqual(r.status, Status.CONSISTENT)
        self.assertEqual(r.key_hex, "a3")

    def test_threshold_equal_to_count_is_vacuously_consistent(self):
        # With exactly k points there is no redundancy: they always define a
        # degree-(k-1) polynomial, so the service reports CONSISTENT.
        rng = random.Random(103)
        key = bytes([9, 8, 7])
        cards = [11, 22, 33, 44]
        shares = make_shares(cards, 4, key, rng)
        v, r = analyze(payload(cards, 4, shares))
        self.assertTrue(v.ok)
        self.assertEqual(r.status, Status.CONSISTENT)
        self.assertEqual(r.key_hex, key.hex())


class RecoveredTests(unittest.TestCase):
    def test_one_bad_card_is_identified(self):
        rng = random.Random(201)
        key = bytes([0xDE, 0xAD, 0xBE, 0xEF])
        for n, k in ((5, 3), (6, 3), (7, 2), (8, 5)):
            cards = list(range(1, n + 1))
            shares = make_shares(cards, k, key, rng)
            bad_index = rng.randrange(n)
            shares[bad_index] = corrupt(shares[bad_index], rng)
            v, r = analyze(payload(cards, k, shares))
            self.assertTrue(v.ok, v.errors)
            self.assertIs(
                r.status,
                Status.RECOVERED,
                f"n={n}, k={k}, bad_index={bad_index}",
            )
            self.assertEqual(r.bad_card, cards[bad_index])
            self.assertEqual(r.key_hex, key.hex())

    def test_corruption_in_single_byte_still_detected(self):
        rng = random.Random(202)
        cards = [3, 5, 8, 13, 21]
        shares = make_shares(cards, 3, b"secret!!", rng)
        shares[1] = corrupt(shares[1], rng, n_bytes=1)
        v, r = analyze(payload(cards, 3, shares))
        self.assertTrue(v.ok)
        self.assertEqual(r.status, Status.RECOVERED)
        self.assertEqual(r.bad_card, 5)
        self.assertEqual(r.key_hex, b"secret!!".hex())

    def test_recovered_key_uses_zero_point(self):
        # Explicit degree-1 polynomial f(x)=7+2x over GF(256); f(0)=7.
        # Shares at x=4..7 are honest; x=8 is corrupted.
        cards = [4, 5, 6, 7, 8]
        honest = [gf.poly_eval([7, 2], x) for x in cards]
        shares = [bytes([v]).hex() for v in honest]
        shares[4] = "ff"
        v, r = analyze(payload(cards, 2, shares))
        self.assertTrue(v.ok)
        self.assertEqual(r.status, Status.RECOVERED)
        self.assertEqual(r.bad_card, 8)
        self.assertEqual(r.key_hex, "07")


class ConflictTests(unittest.TestCase):
    def test_two_bad_cards_conflict(self):
        rng = random.Random(301)
        key = bytes([1, 2, 3, 4])
        cards = [1, 2, 3, 4, 5, 6]
        shares = make_shares(cards, 3, key, rng)
        shares[0] = corrupt(shares[0], rng)
        shares[3] = corrupt(shares[3], rng)
        v, r = analyze(payload(cards, 3, shares))
        self.assertTrue(v.ok)
        self.assertIs(r.status, Status.CONFLICT)
        self.assertIsNone(r.key_hex)
        self.assertIsNone(r.bad_card)

    def test_one_bad_card_without_redundancy_is_conflict(self):
        # n = k+1: excluding ANY card leaves exactly k points, which always
        # define a polynomial. The culprit is not unique, so the service must
        # refuse to name a card or leak a key.
        rng = random.Random(302)
        cards = [1, 2, 3, 4]
        shares = make_shares(cards, 3, b"\x00\x11", rng)
        shares[2] = corrupt(shares[2], rng)
        v, r = analyze(payload(cards, 3, shares))
        self.assertTrue(v.ok)
        self.assertIs(r.status, Status.CONFLICT)
        self.assertIsNone(r.key_hex)
        self.assertIsNone(r.bad_card)

    def test_garbage_shares_conflict_without_key(self):
        rng = random.Random(303)
        cards = [10, 20, 30, 40, 50]
        shares = [bytes(rng.randrange(256) for _ in range(4)).hex()
                  for _ in cards]
        v, r = analyze(payload(cards, 3, shares))
        self.assertTrue(v.ok)
        self.assertIs(r.status, Status.CONFLICT)
        self.assertIsNone(r.key_hex)


class ValidationTests(unittest.TestCase):
    def _bad(self, p):
        v, _ = validate_payload(p)
        self.assertFalse(v.ok)
        return v.errors

    def test_duplicate_card_number_is_locatable(self):
        errs = self._bad(payload([1, 2, 2, 3], 2, ["aa"] * 4))
        dup = [e for e in errs if e.field == "card" and "重复" in e.message]
        self.assertEqual(len(dup), 1)
        self.assertEqual(dup[0].index, 2)

    def test_card_count_out_of_range(self):
        for n in (0, 1, 3, 9, 12):
            errs = self._bad(
                payload(list(range(1, n + 1)), 2, ["aa"] * n)
            ) if n > 0 else self._bad(payload([], 2, []))
            self.assertTrue(
                any(e.field == "cards" for e in errs), f"n={n}"
            )

    def test_card_zero_and_over_255(self):
        errs = self._bad(payload([0, 256, 5, 7], 2, ["aa"] * 4))
        self.assertEqual(
            sorted(e.index for e in errs if e.field == "card"), [0, 1]
        )

    def test_non_integer_card(self):
        errs = self._bad(payload(["a", 2, None, 4.5], 2, ["aa"] * 4))
        self.assertEqual(
            sorted(e.index for e in errs if e.field == "card"), [0, 2, 3]
        )

    def test_threshold_bounds(self):
        for bad_t in (0, 1, -3, 5, 99):
            errs = self._bad(payload([1, 2, 3, 4], bad_t, ["aa"] * 4))
            self.assertTrue(
                any(e.field == "threshold" for e in errs), f"t={bad_t}"
            )

    def test_threshold_not_integer(self):
        errs = self._bad(payload([1, 2, 3, 4], "x", ["aa"] * 4))
        self.assertTrue(any(e.field == "threshold" for e in errs))

    def test_non_hex_share_is_locatable(self):
        errs = self._bad(payload([1, 2, 3, 4], 2, ["ab", "xyz", "12", "9g"]))
        bad = [e for e in errs if e.field == "share"]
        self.assertEqual(sorted(e.index for e in bad), [1, 3])

    def test_odd_length_share(self):
        errs = self._bad(payload([1, 2, 3, 4], 2, ["abc", "ab", "ab", "ab"]))
        self.assertEqual([e.index for e in errs if e.field == "share"], [0])

    def test_unequal_length_reports_original_row(self):
        # Row 0 is invalid hex and must not shift the reported index of the
        # length-mismatched share on row 3.
        shares = ["zz", "aabb", "aabb", "aabbcc"]
        errs = self._bad(payload([1, 2, 3, 4], 2, shares))
        fields = {(e.field, e.index) for e in errs}
        self.assertIn(("share", 0), fields)
        self.assertIn(("share", 3), fields)
        len_err = [e for e in errs if e.field == "share" and e.index == 3][0]
        self.assertIn("长度", len_err.message)

    def test_empty_share(self):
        errs = self._bad(payload([1, 2, 3, 4], 2, ["", "ab", "ab", "ab"]))
        self.assertEqual([e.index for e in errs if e.field == "share"], [0])

    def test_share_count_mismatch(self):
        errs = self._bad(payload([1, 2, 3, 4], 2, ["ab", "ab"]))
        self.assertTrue(any(e.field == "shares" for e in errs))

    def test_wrong_types(self):
        self._bad({"cards": "nope", "threshold": 2, "shares": []})
        self._bad({"cards": [1, 2, 3, 4], "threshold": 2, "shares": "nope"})
        self._bad({"threshold": 2, "shares": ["ab"] * 4})
        self._bad("not-an-object")

    def test_uppercase_hex_accepted(self):
        rng = random.Random(401)
        cards = [1, 2, 3, 4, 5]
        shares = [s.upper() for s in make_shares(cards, 3, b"\x10\x20", rng)]
        v, normalized = validate_payload(payload(cards, 3, shares))
        self.assertTrue(v.ok)
        self.assertTrue(all(s == s.lower() for s in normalized["shares"]))

    def test_valid_boundary_counts(self):
        rng = random.Random(402)
        for n in (MIN_CARDS, MAX_CARDS):
            cards = list(range(1, n + 1))
            shares = make_shares(cards, 2, b"k", rng)
            v, _ = analyze(payload(cards, 2, shares))
            self.assertTrue(v.ok)

    def test_reconstruction_not_run_on_invalid_input(self):
        v, r = analyze(payload([1, 1, 1, 1], 9, ["bad"] * 4))
        self.assertFalse(v.ok)
        self.assertIsNone(r)

    def test_reconstruct_accepts_valid_structured_data(self):
        # Direct normalized-dict path used by the HTTP layer.
        # f(x) = 7 + 2x over GF(256): shares at x=1..4 are 5,3,1,15.
        normalized = {
            "cards": [1, 2, 3, 4],
            "threshold": 2,
            "shares": ["05", "03", "01", "0f"],
        }
        r = reconstruct(normalized)
        self.assertIs(r.status, Status.CONSISTENT)
        self.assertEqual(r.key_hex, "07")


if __name__ == "__main__":
    unittest.main()
