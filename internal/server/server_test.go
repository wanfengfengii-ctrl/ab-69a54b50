package server

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"recovery/internal/shamir"
)

var testSecret = []byte{
	0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67,
	0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76,
}

type seqReader struct{ state uint64 }

func (s *seqReader) Read(p []byte) (int, error) {
	for i := range p {
		s.state = s.state*6364136223846793005 + 1442695040888963407
		p[i] = byte(s.state >> 33)
	}
	return len(p), nil
}

func testPoints(t *testing.T) []shamir.Point {
	t.Helper()
	pts, err := shamir.MakeShares(testSecret, 3, []byte{1, 2, 3, 4, 5}, &seqReader{state: 7})
	if err != nil {
		t.Fatalf("MakeShares: %v", err)
	}
	return pts
}

func bodyOf(threshold int, ids []int, shares []string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, `{"threshold":%d,"cards":[`, threshold)
	for i := range ids {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"id":%d,"share":"%s"}`, ids[i], shares[i])
	}
	sb.WriteString(`]}`)
	return sb.String()
}

func goodBody(t *testing.T) (string, []shamir.Point) {
	t.Helper()
	pts := testPoints(t)
	ids := make([]int, len(pts))
	shares := make([]string, len(pts))
	for i, p := range pts {
		ids[i] = int(p.X)
		shares[i] = hex.EncodeToString(p.Y)
	}
	return bodyOf(3, ids, shares), pts
}

func post(t *testing.T, body string) (int, map[string]any, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/recovery/reconstruct", strings.NewReader(body))
	rec := httptest.NewRecorder()
	New().ServeHTTP(rec, req)
	var parsed map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &parsed)
	return rec.Code, parsed, rec.Body.String()
}

func errorFields(t *testing.T, body map[string]any) []string {
	t.Helper()
	list, ok := body["errors"].([]any)
	if !ok {
		t.Fatalf("响应缺少 errors 数组: %v", body)
	}
	var out []string
	for _, e := range list {
		if em, ok := e.(map[string]any); ok {
			out = append(out, fmt.Sprint(em["field"]))
		}
	}
	return out
}

func hasField(fields []string, want string) bool {
	for _, f := range fields {
		if f == want {
			return true
		}
	}
	return false
}

func TestHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	New().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ok") {
		t.Fatalf("health: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestIndexPage(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	New().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "恢复") {
		t.Fatalf("index: code=%d", rec.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/recovery/reconstruct", nil)
	rec := httptest.NewRecorder()
	New().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/recovery/reconstruct: code=%d, want 405", rec.Code)
	}
}

func TestReconstructConsistent(t *testing.T) {
	body, _ := goodBody(t)
	code, resp, _ := post(t, body)
	if code != http.StatusOK || resp["status"] != "CONSISTENT" {
		t.Fatalf("code=%d resp=%v", code, resp)
	}
	if resp["key"] != hex.EncodeToString(testSecret) {
		t.Fatalf("key=%v", resp["key"])
	}
}

func TestReconstructRecovered(t *testing.T) {
	_, pts := goodBody(t)
	pts[3].Y[0] ^= 0x01 // 编号 4 的卡抄错一个字节
	ids := make([]int, len(pts))
	shares := make([]string, len(pts))
	for i, p := range pts {
		ids[i] = int(p.X)
		shares[i] = hex.EncodeToString(p.Y)
	}
	code, resp, _ := post(t, bodyOf(3, ids, shares))
	if code != http.StatusOK || resp["status"] != "RECOVERED" {
		t.Fatalf("code=%d resp=%v", code, resp)
	}
	if resp["excludedCardId"] != float64(4) {
		t.Fatalf("excludedCardId=%v, want 4", resp["excludedCardId"])
	}
	if resp["key"] != hex.EncodeToString(testSecret) {
		t.Fatalf("key=%v", resp["key"])
	}
}

// TestConflictNeverLeaksKey 确保 CONFLICT 响应既无 key 字段，也不含密钥内容。
func TestConflictNeverLeaksKey(t *testing.T) {
	_, pts := goodBody(t)
	pts[3].Y[0] ^= 0x01
	pts[4].Y[1] ^= 0x02
	ids := make([]int, len(pts))
	shares := make([]string, len(pts))
	for i, p := range pts {
		ids[i] = int(p.X)
		shares[i] = hex.EncodeToString(p.Y)
	}
	code, resp, raw := post(t, bodyOf(3, ids, shares))
	if code != http.StatusOK || resp["status"] != "CONFLICT" {
		t.Fatalf("code=%d resp=%v", code, resp)
	}
	if _, leaked := resp["key"]; leaked {
		t.Fatal("CONFLICT 响应泄露了 key 字段")
	}
	if strings.Contains(raw, hex.EncodeToString(testSecret)) {
		t.Fatal("CONFLICT 响应包含密钥内容")
	}
}

func TestValidationErrors(t *testing.T) {
	good, pts := goodBody(t)
	_ = good
	ids := []int{1, 2, 3, 4, 5}
	shares := make([]string, len(pts))
	for i, p := range pts {
		shares[i] = hex.EncodeToString(p.Y)
	}

	short := shares[4][:len(shares[4])-2]
	manyIDs := []int{1, 2, 3, 4, 5, 6, 7, 8, 9}
	manyShares := make([]string, 9)
	for i := range manyShares {
		manyShares[i] = shares[0]
	}

	cases := []struct {
		name      string
		body      string
		wantField string
	}{
		{"编号重复", bodyOf(3, []int{1, 1, 3, 4, 5}, shares), "cards[1].id"},
		{"编号为零", bodyOf(3, []int{0, 2, 3, 4, 5}, shares), "cards[0].id"},
		{"编号超界", bodyOf(3, []int{256, 2, 3, 4, 5}, shares), "cards[0].id"},
		{"份额非十六进制", bodyOf(3, ids, []string{"zz99", shares[1], shares[2], shares[3], shares[4]}), "cards[0].share"},
		{"份额奇数长度", bodyOf(3, ids, []string{"abc", shares[1], shares[2], shares[3], shares[4]}), "cards[0].share"},
		{"份额为空", bodyOf(3, ids, []string{"", shares[1], shares[2], shares[3], shares[4]}), "cards[0].share"},
		{"份额不等长", bodyOf(3, ids, []string{shares[0], shares[1], shares[2], shares[3], short}), "cards[4].share"},
		{"门限为 1", bodyOf(1, ids, shares), "threshold"},
		{"门限为 0", bodyOf(0, ids, shares), "threshold"},
		{"门限大于卡片数", bodyOf(6, ids, shares), "threshold"},
		{"门限非整数", `{"threshold":2.5,"cards":[{"id":1,"share":"00"}]}`, "threshold"},
		{"卡片过少", bodyOf(2, ids[:3], shares[:3]), "cards"},
		{"卡片过多", bodyOf(3, manyIDs, manyShares), "cards"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, resp, raw := post(t, c.body)
			if code != http.StatusBadRequest {
				t.Fatalf("code=%d, want 400; body=%s", code, raw)
			}
			if !hasField(errorFields(t, resp), c.wantField) {
				t.Fatalf("错误未定位到 %q: %s", c.wantField, raw)
			}
		})
	}
}

func TestInvalidJSON(t *testing.T) {
	code, resp, _ := post(t, "not json")
	if code != http.StatusBadRequest {
		t.Fatalf("code=%d, want 400", code)
	}
	if resp["status"] != "INVALID" {
		t.Fatalf("resp=%v", resp)
	}
}
