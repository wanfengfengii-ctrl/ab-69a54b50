// Package gf256 实现 GF(2^8) 上的有限域运算，
// 模既约多项式 x^8 + x^4 + x^3 + x + 1（0x11b，与 AES 相同）。
package gf256

// reduction 是 0x11b 的低 8 位，用于乘法约减。
const reduction = 0x1b

// Add 即逐位异或（GF(2) 上的加法）。
func Add(a, b byte) byte { return a ^ b }

// Mul 返回 a 与 b 在 GF(2^8) 上的乘积（俄罗斯农民乘法 + 模约减）。
func Mul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 == 1 {
			p ^= a
		}
		carry := a&0x80 != 0
		a <<= 1
		if carry {
			a ^= reduction
		}
		b >>= 1
	}
	return p
}

// Pow 返回 a^e。约定 0^0 = 1。
func Pow(a byte, e uint16) byte {
	r := byte(1)
	for e > 0 {
		if e&1 == 1 {
			r = Mul(r, a)
		}
		a = Mul(a, a)
		e >>= 1
	}
	return r
}

// Inv 返回乘法逆元 a^254。Inv(0) 返回 0，调用方必须避免对 0 求逆。
func Inv(a byte) byte {
	if a == 0 {
		return 0
	}
	return Pow(a, 254)
}

// Div 返回 a/b。b 为 0 时 panic。
func Div(a, b byte) byte {
	if b == 0 {
		panic("gf256: division by zero")
	}
	return Mul(a, Inv(b))
}
