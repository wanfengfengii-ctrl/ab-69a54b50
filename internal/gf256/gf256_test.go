package gf256

import "testing"

func TestMulKnownVectors(t *testing.T) {
	// FIPS-197 中 AES 域（同为 0x11b）的已知乘法结果。
	cases := []struct{ a, b, want byte }{
		{0x57, 0x83, 0xc1}, // FIPS-197 §4.2 示例
		{0x57, 0x13, 0xfe}, // FIPS-197 xtime 链示例
		{0x02, 0x80, 0x1b}, // xtime 进位约减
		{0x00, 0xff, 0x00},
		{0x01, 0x00, 0x00},
		{0x01, 0xff, 0xff},
	}
	for _, c := range cases {
		if got := Mul(c.a, c.b); got != c.want {
			t.Errorf("Mul(%02x, %02x) = %02x, want %02x", c.a, c.b, got, c.want)
		}
		if got := Mul(c.b, c.a); got != c.want {
			t.Errorf("Mul(%02x, %02x) = %02x (交换), want %02x", c.b, c.a, got, c.want)
		}
	}
}

func TestInverseExhaustive(t *testing.T) {
	for a := 1; a < 256; a++ {
		if got := Mul(byte(a), Inv(byte(a))); got != 1 {
			t.Fatalf("Mul(%02x, Inv(%02x)) = %02x, want 01", a, a, got)
		}
	}
}

func TestDivRoundTrip(t *testing.T) {
	for a := 0; a < 256; a += 17 {
		for b := 1; b < 256; b += 31 {
			if got := Mul(Div(byte(a), byte(b)), byte(b)); got != byte(a) {
				t.Fatalf("Div 往返失败: a=%02x b=%02x got=%02x", a, b, got)
			}
		}
	}
}

func TestAddIsXor(t *testing.T) {
	if Add(0xa5, 0x5a) != 0xff || Add(0xa5, 0xa5) != 0x00 {
		t.Fatal("域加法应为逐位异或")
	}
}

func TestMulDistributive(t *testing.T) {
	for a := 1; a < 256; a += 61 {
		for b := 0; b < 256; b += 47 {
			for c := 0; c < 256; c += 89 {
				l := Mul(byte(a), Add(byte(b), byte(c)))
				r := Add(Mul(byte(a), byte(b)), Mul(byte(a), byte(c)))
				if l != r {
					t.Fatalf("分配律失败: a=%02x b=%02x c=%02x", a, b, c)
				}
			}
		}
	}
}
