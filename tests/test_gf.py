"""Unit tests for GF(256) arithmetic."""

import random
import unittest

from app import gf


class GFTests(unittest.TestCase):
    def test_add_is_xor_and_self_inverse(self):
        for a in range(256):
            for b in (0, 1, 55, 128, 255):
                self.assertEqual(gf.add(a, b), a ^ b)
            self.assertEqual(gf.add(a, a), 0)

    def test_mul_identity_and_zero(self):
        for a in range(256):
            self.assertEqual(gf.mul(a, 0), 0)
            self.assertEqual(gf.mul(a, 1), a)

    def test_exp_log_tables(self):
        # Generator 3 must be primitive: every non-zero value appears once.
        self.assertEqual(sorted(gf._EXP[:255]), list(range(1, 256)))
        for x in range(1, 256):
            self.assertEqual(gf._EXP[gf._LOG[x]], x)

    def test_mul_field_laws(self):
        rng = random.Random(42)
        values = [rng.randrange(256) for _ in range(200)]
        for a, b, c in zip(values[::3], values[1::3], values[2::3]):
            # commutativity
            self.assertEqual(gf.mul(a, b), gf.mul(b, a))
            # associativity
            self.assertEqual(
                gf.mul(gf.mul(a, b), c), gf.mul(a, gf.mul(b, c))
            )
            # distributivity over XOR
            self.assertEqual(gf.mul(a, b ^ c), gf.mul(a, b) ^ gf.mul(a, c))

    def test_inverse_and_div(self):
        for a in range(1, 256):
            inv = gf.inverse(a)
            self.assertEqual(gf.mul(a, inv), 1)
            self.assertEqual(gf.div(a, a), 1)
            self.assertEqual(gf.div(0, a), 0)
        with self.assertRaises(ZeroDivisionError):
            gf.inverse(0)
        with self.assertRaises(ZeroDivisionError):
            gf.div(1, 0)

    def test_poly_eval_constant_and_linear(self):
        self.assertEqual(gf.poly_eval([17], 99), 17)
        # f(x) = 5 + 3x ; f(2) = 5 + 6 = 3
        self.assertEqual(gf.poly_eval([5, 3], 2), gf.add(5, gf.mul(3, 2)))

    def test_lagrange_recovers_random_polynomials(self):
        rng = random.Random(7)
        for degree in range(0, 6):
            for _ in range(20):
                coeffs = [rng.randrange(256) for _ in range(degree + 1)]
                xs = rng.sample(range(1, 256), degree + 1)
                points = [(x, gf.poly_eval(coeffs, x)) for x in xs]
                # f(0) is the constant coefficient
                self.assertEqual(gf.lagrange_eval(points, 0), coeffs[0])
                # evaluations at other points match as well
                for x in rng.sample(range(1, 256), 5):
                    self.assertEqual(
                        gf.lagrange_eval(points, x), gf.poly_eval(coeffs, x)
                    )

    def test_lagrange_rejects_duplicate_x_via_caller(self):
        # Distinct-x is a precondition; sanity-check two points with same x
        # and different y do not produce a "valid" interpolation silently
        # in reconstruction (covered at higher level); here just confirm
        # division path is stable with coincident denominators equal 0.
        with self.assertRaises(ZeroDivisionError):
            gf.lagrange_eval([(5, 1), (5, 2)], 0)


if __name__ == "__main__":
    unittest.main()
