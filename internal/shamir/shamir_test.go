package shamir

import (
	"bytes"
	"testing"
)

// seqReader 是确定性字节流，保证测试可复现。
type seqReader struct{ state uint64 }

func (s *seqReader) Read(p []byte) (int, error) {
	for i := range p {
		s.state = s.state*6364136223846793005 + 1442695040888963407
		p[i] = byte(s.state >> 33)
	}
	return len(p), nil
}

var testSecret = []byte{
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
}

func makeTestShares(t *testing.T, secret []byte, threshold int, xs []byte) []Point {
	t.Helper()
	pts, err := MakeShares(secret, threshold, xs, &seqReader{state: 0xC0FFEE})
	if err != nil {
		t.Fatalf("MakeShares: %v", err)
	}
	return pts
}

func clonePoints(pts []Point) []Point {
	out := make([]Point, len(pts))
	for i, p := range pts {
		y := make([]byte, len(p.Y))
		copy(y, p.Y)
		out[i] = Point{X: p.X, Y: y}
	}
	return out
}

// TestEvalPolyKnownVector 使用手算向量：f(x) = 0x53 + 0xca·x（模 0x11b），
// f(1)=0x99，f(2)=0xdc，f(0)=0x53。
func TestEvalPolyKnownVector(t *testing.T) {
	if got := evalPoly([]byte{0x53, 0xca}, 1); got != 0x99 {
		t.Errorf("f(1) = %02x, want 99", got)
	}
	if got := evalPoly([]byte{0x53, 0xca}, 2); got != 0xdc {
		t.Errorf("f(2) = %02x, want dc", got)
	}
	pts := []Point{{X: 1, Y: []byte{0x99}}, {X: 2, Y: []byte{0xdc}}}
	if got := Key(pts, 2); !bytes.Equal(got, []byte{0x53}) {
		t.Errorf("key = %x, want 53", got)
	}
}

func TestAnalyzeConsistent(t *testing.T) {
	pts := makeTestShares(t, testSecret, 3, []byte{1, 2, 3, 4, 5})
	res := Analyze(pts, 3)
	if res.Status != StatusConsistent {
		t.Fatalf("status = %s, want CONSISTENT", res.Status)
	}
	if !bytes.Equal(res.Key, testSecret) {
		t.Fatalf("key = %x, want %x", res.Key, testSecret)
	}
}

// TestKeyFromEveryThresholdSubset 验证任意门限个份额都还原同一密钥。
func TestKeyFromEveryThresholdSubset(t *testing.T) {
	pts := makeTestShares(t, testSecret, 3, []byte{1, 2, 3, 4, 5})
	for a := 0; a < 3; a++ {
		for b := a + 1; b < 4; b++ {
			for c := b + 1; c < 5; c++ {
				sub := []Point{pts[a], pts[b], pts[c]}
				if got := Key(sub, 3); !bytes.Equal(got, testSecret) {
					t.Errorf("子集(%d,%d,%d): key = %x", a, b, c, got)
				}
			}
		}
	}
}

// TestAnalyzeRecoveredSingleCorruption 模拟一张卡被抄错：必须 RECOVERED，
// 且正确指出问题卡编号并给出正确密钥。
func TestAnalyzeRecoveredSingleCorruption(t *testing.T) {
	xs := []byte{1, 2, 3, 4, 5}
	base := makeTestShares(t, testSecret, 3, xs)
	for k := range base {
		pts := clonePoints(base)
		pts[k].Y[0] ^= 0x01
		res := Analyze(pts, 3)
		if res.Status != StatusRecovered {
			t.Fatalf("抄错卡 %d: status = %s, want RECOVERED", xs[k], res.Status)
		}
		if res.Excluded != xs[k] {
			t.Errorf("excluded = %d, want %d", res.Excluded, xs[k])
		}
		if !bytes.Equal(res.Key, testSecret) {
			t.Errorf("key = %x, want %x", res.Key, testSecret)
		}
	}
}

// TestAnalyzeConflictTwoCorruptions 两张卡抄错时必须 CONFLICT 且不带密钥。
func TestAnalyzeConflictTwoCorruptions(t *testing.T) {
	pts := makeTestShares(t, testSecret, 3, []byte{1, 2, 3, 4, 5})
	pts[1].Y[0] ^= 0x01
	pts[3].Y[2] ^= 0x40
	res := Analyze(pts, 3)
	if res.Status != StatusConflict {
		t.Fatalf("status = %s, want CONFLICT", res.Status)
	}
	if res.Key != nil {
		t.Fatalf("CONFLICT 不得携带密钥: %x", res.Key)
	}
}

// TestAnalyzeThresholdEqualsCardCount 门限等于卡片数量时没有任何冗余：
// 任意 n 个点都落在唯一的 n-1 阶多项式上，因此永远判定 CONSISTENT，
// 抄错在该配置下数学上不可检测。
func TestAnalyzeThresholdEqualsCardCount(t *testing.T) {
	pts := makeTestShares(t, testSecret, 5, []byte{1, 2, 3, 4, 5})
	pts[2].Y[0] ^= 0x01
	if res := Analyze(pts, 5); res.Status != StatusConsistent {
		t.Fatalf("status = %s, want CONSISTENT（无冗余时无法检测错误）", res.Status)
	}
}

// TestAnalyzeConflictAmbiguousMinimal 卡片数 = 门限 + 1 时，剔除任意一张
// 剩余份额都「一致」，无法唯一定位问题卡，必须 CONFLICT。
func TestAnalyzeConflictAmbiguousMinimal(t *testing.T) {
	pts := makeTestShares(t, testSecret, 3, []byte{1, 2, 3, 4})
	pts[0].Y[0] ^= 0x01
	if res := Analyze(pts, 3); res.Status != StatusConflict {
		t.Fatalf("status = %s, want CONFLICT", res.Status)
	}
}

func TestConsistentShortSets(t *testing.T) {
	pts := makeTestShares(t, testSecret, 3, []byte{1, 2, 3, 4, 5})
	if !Consistent(pts[:2], 3) {
		t.Fatal("少于门限的点集应视为一致")
	}
	if !Consistent(pts[:3], 3) {
		t.Fatal("恰好门限个点应视为一致")
	}
}

func TestMakeSharesErrors(t *testing.T) {
	rng := &seqReader{state: 1}
	if _, err := MakeShares(testSecret, 0, []byte{1, 2}, rng); err == nil {
		t.Error("门限 0 应报错")
	}
	if _, err := MakeShares(testSecret, 3, []byte{1, 2}, rng); err == nil {
		t.Error("门限大于份额数应报错")
	}
	if _, err := MakeShares(nil, 2, []byte{1, 2}, rng); err == nil {
		t.Error("空密钥应报错")
	}
	if _, err := MakeShares(testSecret, 2, []byte{0, 2}, rng); err == nil {
		t.Error("零横坐标应报错")
	}
	if _, err := MakeShares(testSecret, 2, []byte{2, 2}, rng); err == nil {
		t.Error("重复横坐标应报错")
	}
}
