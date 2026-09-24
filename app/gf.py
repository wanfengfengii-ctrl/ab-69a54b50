"""GF(2^8) finite field arithmetic.

Field: AES/Rijndael polynomial x^8 + x^4 + x^3 + x + 1 (modulus 0x11B),
with generator 3. Addition and subtraction are XOR.
"""

_MODULUS = 0x11B

# exp table is doubled in length so that exponents up to 508 can be looked
# up without an extra modulo operation.
_EXP = [0] * 512
_LOG = [0] * 256


def _build_tables() -> None:
    # Powers of the primitive element 3: x_{i+1} = 3 * x_i = 2 * x_i ^ x_i.
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        doubled = x << 1
        if doubled & 0x100:
            doubled ^= _MODULUS
        x = doubled ^ x
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_build_tables()


def add(a: int, b: int) -> int:
    return a ^ b


def mul(a: int, b: int) -> int:
    """Multiply two field elements."""
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def div(a: int, b: int) -> int:
    """Divide a by b in the field. b must be non-zero."""
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(256)")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def inverse(a: int) -> int:
    """Multiplicative inverse of a non-zero element."""
    if a == 0:
        raise ZeroDivisionError("zero has no inverse in GF(256)")
    return _EXP[255 - _LOG[a]]


def poly_eval(coeffs: list[int], x: int) -> int:
    """Evaluate polynomial (coeffs low-to-high) at point x using Horner."""
    result = 0
    for c in reversed(coeffs):
        result = mul(result, x) ^ c
    return result


def lagrange_eval(points: list[tuple[int, int]], x: int) -> int:
    """Evaluate the interpolation polynomial at x.

    All x-coordinates must be distinct. Used both to recover f(0) and to
    verify that a point lies on the polynomial implied by other shares.
    """
    total = 0
    for i, (xi, yi) in enumerate(points):
        numerator = 1
        denominator = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            # In characteristic 2 subtraction equals addition (XOR).
            numerator = mul(numerator, x ^ xj)
            denominator = mul(denominator, xi ^ xj)
        total ^= mul(yi, div(numerator, denominator))
    return total
