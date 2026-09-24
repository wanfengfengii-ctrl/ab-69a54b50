// Package shamir 在 GF(256) 上实现门限秘密共享的重建与一致性判定。
//
// 每张恢复卡是一个点：横坐标 X 为卡的唯一非零编号，纵坐标 Y 为份额字节串。
// 合法份额落在同一个「门限值 − 1」阶多项式上，该多项式在零点处的值即恢复密钥。
package shamir

import (
	"bytes"
	"errors"
	"io"

	"recovery/internal/gf256"
)

// Point 是一张恢复卡对应的点。X 为 1–255 的非零编号，Y 为等长的份额字节。
type Point struct {
	X byte
	Y []byte
}

// Status 是 Analyze 的判定结论。
type Status string

const (
	// StatusConsistent 表示全部份额一致，Key 为恢复密钥。
	StatusConsistent Status = "CONSISTENT"
	// StatusRecovered 表示剔除唯一一张问题卡后其余份额一致，
	// Excluded 为问题卡编号，Key 为恢复密钥。
	StatusRecovered Status = "RECOVERED"
	// StatusConflict 表示份额相互矛盾或无法唯一定位问题卡，
	// 此时 Key 必须为空，绝不能泄露任何密钥。
	StatusConflict Status = "CONFLICT"
)

// Result 是 Analyze 的判定结果。仅当 Status 为 CONSISTENT 或 RECOVERED 时
// Key 非空；仅当 Status 为 RECOVERED 时 Excluded 非零。
type Result struct {
	Status   Status
	Key      []byte
	Excluded byte
}

// evalAt 返回经过 pts 的唯一次数 ≤ len(pts)-1 多项式在 x 处的值（逐字节拉格朗日插值）。
// 在 GF(2) 扩域上减法即加法，故 (x - x_j) 与 (x_i - x_j) 均写作异或。
func evalAt(pts []Point, x byte) []byte {
	out := make([]byte, len(pts[0].Y))
	for i := range pts {
		num := byte(1)
		den := byte(1)
		for j := range pts {
			if i == j {
				continue
			}
			num = gf256.Mul(num, x^pts[j].X)
			den = gf256.Mul(den, pts[i].X^pts[j].X)
		}
		c := gf256.Div(num, den)
		for b := range out {
			out[b] ^= gf256.Mul(pts[i].Y[b], c)
		}
	}
	return out
}

// Key 返回份额对应的恢复密钥（多项式零点值）。pts 至少要有 threshold 个点，
// 取前 threshold 个即可；一致的点集中任意 threshold 个点给出相同结果。
func Key(pts []Point, threshold int) []byte {
	return evalAt(pts[:threshold], 0)
}

// Consistent 报告全部点是否落在同一个次数 ≤ threshold-1 的多项式上。
// 点数不超过 threshold 时必然一致（唯一插值多项式总是存在）。
func Consistent(pts []Point, threshold int) bool {
	if len(pts) <= threshold {
		return true
	}
	basis := pts[:threshold]
	for _, p := range pts[threshold:] {
		if !bytes.Equal(evalAt(basis, p.X), p.Y) {
			return false
		}
	}
	return true
}

// Analyze 按恢复策略判定份额集合：
//
//  1. 全部一致 → CONSISTENT，输出密钥；
//  2. 否则，若剔除唯一一张卡后其余（不少于门限值）份额一致 → RECOVERED，
//     输出问题卡编号与密钥；
//  3. 其余情况 → CONFLICT，不输出密钥。
//
// 注意：当卡片数量 = 门限值 + 1 时，任意剔除一张后剩余点数恰等于门限值，
// 必然「一致」，此时无法唯一定位问题卡（候选不唯一），只能判 CONFLICT；
// 门限值等于卡片数量时没有任何冗余，任意点集都「一致」（CONSISTENT），
// 该配置下抄错在数学上不可检测。
func Analyze(pts []Point, threshold int) Result {
	if threshold < 1 || len(pts) < threshold {
		return Result{Status: StatusConflict}
	}
	if Consistent(pts, threshold) {
		return Result{Status: StatusConsistent, Key: Key(pts, threshold)}
	}

	candidates := 0
	var survivors []Point
	var excluded byte
	for i := range pts {
		rest := make([]Point, 0, len(pts)-1)
		rest = append(rest, pts[:i]...)
		rest = append(rest, pts[i+1:]...)
		if len(rest) >= threshold && Consistent(rest, threshold) {
			candidates++
			survivors = rest
			excluded = pts[i].X
		}
	}
	if candidates == 1 {
		return Result{Status: StatusRecovered, Key: Key(survivors, threshold), Excluded: excluded}
	}
	return Result{Status: StatusConflict}
}

// MakeShares 用 rng 提供的高阶系数，把 secret 拆分为各横坐标 xs 上的份额，
// 多项式次数为 threshold-1（常数项即 secret 对应字节）。仅用于测试与验收。
func MakeShares(secret []byte, threshold int, xs []byte, rng io.Reader) ([]Point, error) {
	if len(secret) == 0 {
		return nil, errors.New("shamir: 密钥不能为空")
	}
	if threshold < 1 || threshold > len(xs) {
		return nil, errors.New("shamir: 门限值越界")
	}
	coeffs := make([][]byte, len(secret))
	for b := range secret {
		coeffs[b] = make([]byte, threshold)
		coeffs[b][0] = secret[b]
		if _, err := io.ReadFull(rng, coeffs[b][1:]); err != nil {
			return nil, err
		}
	}

	seen := make(map[byte]bool, len(xs))
	pts := make([]Point, len(xs))
	for i, x := range xs {
		if x == 0 {
			return nil, errors.New("shamir: 横坐标必须非零")
		}
		if seen[x] {
			return nil, errors.New("shamir: 横坐标重复")
		}
		seen[x] = true
		y := make([]byte, len(secret))
		for b := range secret {
			y[b] = evalPoly(coeffs[b], x)
		}
		pts[i] = Point{X: x, Y: y}
	}
	return pts, nil
}

// evalPoly 用霍纳法则求值系数多项式（coeffs[0] 为常数项）。
func evalPoly(coeffs []byte, x byte) byte {
	acc := byte(0)
	for i := len(coeffs) - 1; i >= 0; i-- {
		acc = gf256.Mul(acc, x) ^ coeffs[i]
	}
	return acc
}
