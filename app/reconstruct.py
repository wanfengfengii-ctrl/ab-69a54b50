"""Share validation and key reconstruction over GF(256).

Input contract
--------------
* cards: 4..8 unique, non-zero card numbers (integers 1..255)
* threshold k: 2..len(cards)
* every share is a hex string of the same, even, non-zero length; each byte
  is the y-value of the same degree-(k-1) polynomial at x = card number.

Result model
------------
* CONSISTENT - all shares lie on one polynomial; the key is f(0).
* RECOVERED - removing exactly one card makes the remaining (at least k)
  shares consistent; the bad card and the key are reported.
* CONFLICT  - otherwise; the key must never be disclosed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from . import gf

MIN_CARDS = 4
MAX_CARDS = 8
MIN_THRESHOLD = 2
MAX_CARD_ID = 255
HEX_ALPHABET = set("0123456789abcdefABCDEF")


class Status(str, Enum):
    CONSISTENT = "CONSISTENT"
    RECOVERED = "RECOVERED"
    CONFLICT = "CONFLICT"


@dataclass
class FieldError:
    field: str
    index: int | None
    message: str

    def to_dict(self) -> dict:
        out = {"field": self.field, "message": self.message}
        if self.index is not None:
            out["index"] = self.index
        return out


@dataclass
class ValidationResult:
    errors: list[FieldError] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


@dataclass
class ReconstructionResult:
    status: Status
    key_hex: str | None = None
    bad_card: int | None = None


def _parse_int(raw) -> tuple[int | None, bool]:
    """Return (value, ok). Empty/non-integer is not ok."""
    if isinstance(raw, bool):
        return None, False
    if isinstance(raw, int):
        return raw, True
    if isinstance(raw, str) and raw.strip():
        try:
            return int(raw.strip(), 10), True
        except ValueError:
            return None, False
    return None, False


def validate_payload(payload: dict) -> tuple[ValidationResult, dict]:
    """Validate the raw JSON payload.

    Returns (errors, normalized {"cards": [int], "threshold": int,
    "shares": [str]}). Validation never raises on malformed user input.
    """
    errors: list[FieldError] = []
    normalized: dict = {"cards": [], "threshold": None, "shares": []}

    if not isinstance(payload, dict):
        errors.append(FieldError("payload", None, "请求体必须是 JSON 对象"))
        return ValidationResult(errors), normalized

    # ---- cards ----------------------------------------------------------------
    raw_cards = payload.get("cards")
    cards: list[int] = []
    if not isinstance(raw_cards, list):
        errors.append(FieldError("cards", None, "cards 必须是数组"))
    else:
        if not (MIN_CARDS <= len(raw_cards) <= MAX_CARDS):
            errors.append(
                FieldError(
                    "cards",
                    None,
                    f"卡片数量必须在 {MIN_CARDS} 到 {MAX_CARDS} 之间，当前为 {len(raw_cards)}",
                )
            )
        seen: dict[int, int] = {}
        for i, raw in enumerate(raw_cards):
            value, ok = _parse_int(raw)
            if not ok:
                errors.append(
                    FieldError("card", i, "编号必须是非零整数（1-255）")
                )
                continue
            if not (1 <= value <= MAX_CARD_ID):
                errors.append(
                    FieldError(
                        "card", i, f"编号 {value} 越界，必须在 1-255 之间"
                    )
                )
                continue
            if value in seen:
                errors.append(
                    FieldError(
                        "card",
                        i,
                        f"编号 {value} 与第 {seen[value] + 1} 行重复，编号必须唯一",
                    )
                )
                continue
            seen[value] = i
            cards.append(value)

    # ---- threshold ------------------------------------------------------------
    threshold = None
    raw_t = payload.get("threshold")
    t_value, t_ok = _parse_int(raw_t)
    card_count = len(raw_cards) if isinstance(raw_cards, list) else None
    if not t_ok:
        errors.append(FieldError("threshold", None, "门限值必须是整数"))
    elif card_count is not None and not (
        MIN_THRESHOLD <= t_value <= card_count
    ):
        errors.append(
            FieldError(
                "threshold",
                None,
                f"门限值必须在 {MIN_THRESHOLD} 到卡片数量 {card_count} 之间，"
                f"当前为 {t_value}",
            )
        )
    else:
        threshold = t_value

    # ---- shares ---------------------------------------------------------------
    raw_shares = payload.get("shares")
    shares: list[str] = []
    if not isinstance(raw_shares, list):
        errors.append(FieldError("shares", None, "shares 必须是数组"))
    else:
        if isinstance(raw_cards, list) and len(raw_shares) != len(raw_cards):
            errors.append(
                FieldError(
                    "shares",
                    None,
                    f"份额数量 {len(raw_shares)} 与卡片数量 {len(raw_cards)} 不一致",
                )
            )
        lengths: list[tuple[int, str]] = []
        for i, raw in enumerate(raw_shares):
            if not isinstance(raw, str):
                errors.append(FieldError("share", i, "份额必须是十六进制字符串"))
                continue
            s = raw.strip()
            if not s:
                errors.append(FieldError("share", i, "份额不能为空"))
                continue
            if any(c not in HEX_ALPHABET for c in s):
                errors.append(
                    FieldError(
                        "share", i, "含有非十六进制字符，仅允许 0-9 与 a-f/A-F"
                    )
                )
                continue
            if len(s) % 2 != 0:
                errors.append(
                    FieldError(
                        "share", i, f"长度 {len(s)} 为奇数，十六进制字节串长度必须为偶数"
                    )
                )
                continue
            shares.append(s.lower())
            lengths.append((i, s))

        if lengths:
            ref_index, ref_share = lengths[0]
            for raw_index, s in lengths[1:]:
                if len(s) != len(ref_share):
                    errors.append(
                        FieldError(
                            "share",
                            raw_index,
                            f"份额长度 {len(s)} 与第 {ref_index + 1} 行长度 "
                            f"{len(ref_share)} 不一致，所有份额必须等长",
                        )
                    )

    normalized = {
        "cards": cards,
        "threshold": threshold,
        "shares": shares,
    }
    return ValidationResult(errors), normalized


def _share_bytes(share_hex: str) -> list[int]:
    return [int(share_hex[i : i + 2], 16) for i in range(0, len(share_hex), 2)]


def points_consistent(
    points: list[tuple[int, list[int]]], threshold: int
) -> tuple[bool, list[int] | None]:
    """Check that points lie on one degree-(threshold-1) polynomial.

    The first ``threshold`` points define the interpolated polynomial; each
    remaining point must lie on it. Returns (ok, key bytes at x=0).
    """
    if len(points) < threshold:
        return False, None
    basis = points[:threshold]
    width = len(basis[0][1])
    key = bytearray(width)
    for byte_index in range(width):
        ref = [(x, ys[byte_index]) for x, ys in basis]
        key[byte_index] = gf.lagrange_eval(ref, 0)
        for x, ys in points[threshold:]:
            if gf.lagrange_eval(ref, x) != ys[byte_index]:
                return False, None
    return True, bytes(key)


def reconstruct(normalized: dict) -> ReconstructionResult:
    """Run the full analysis on validated, normalized data."""
    cards: list[int] = normalized["cards"]
    threshold: int = normalized["threshold"]
    shares: list[str] = normalized["shares"]

    points = [(cards[i], _share_bytes(shares[i])) for i in range(len(cards))]

    ok, key = points_consistent(points, threshold)
    if ok:
        return ReconstructionResult(
            Status.CONSISTENT, key_hex=key.hex()
        )

    # Try excluding each single card; the rest must number at least threshold
    # and all agree on one polynomial.
    candidates: list[tuple[int, bytes]] = []
    for skip in range(len(points)):
        remaining = points[:skip] + points[skip + 1 :]
        if len(remaining) < threshold:
            continue
        ok, key = points_consistent(remaining, threshold)
        if ok:
            candidates.append((points[skip][0], key))

    if len(candidates) == 1:
        bad_card, key = candidates[0]
        return ReconstructionResult(
            Status.RECOVERED, key_hex=key.hex(), bad_card=bad_card
        )

    # Zero candidates => genuine conflict. More than one => data does not
    # identify a unique culprit/key; treat as conflict as well.
    return ReconstructionResult(Status.CONFLICT)


def analyze(payload: dict) -> tuple[ValidationResult, ReconstructionResult | None]:
    """Validate then reconstruct. ReconstructionResult is None on bad input."""
    result, normalized = validate_payload(payload)
    if not result.ok:
        return result, None
    return result, reconstruct(normalized)
