// Command verify 对运行中的恢复密钥服务执行 HTTP 冒烟验收。
// 全部检查通过以退出码 0 结束，任一失败以退出码 1 结束。
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"recovery/internal/shamir"
)

// secretHex 是验收用的已知密钥，CONSISTENT / RECOVERED 必须还原出它。
const secretHex = "00112233445566778899aabbccddeeff"

// seqReader 是确定性字节流，保证每次验收使用相同的多项式系数。
type seqReader struct{ state uint64 }

func (s *seqReader) Read(p []byte) (int, error) {
	for i := range p {
		s.state = s.state*6364136223846793005 + 1442695040888963407
		p[i] = byte(s.state >> 33)
	}
	return len(p), nil
}

// testShares 生成 5 张卡（编号 1–5）、门限 3 的合法份额。
func testShares() []shamir.Point {
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		panic(err)
	}
	pts, err := shamir.MakeShares(secret, 3, []byte{1, 2, 3, 4, 5}, &seqReader{state: 2024})
	if err != nil {
		panic(err)
	}
	return pts
}

func payload(pts []shamir.Point, threshold int) map[string]any {
	cards := make([]map[string]any, len(pts))
	for i, p := range pts {
		cards[i] = map[string]any{"id": int(p.X), "share": hex.EncodeToString(p.Y)}
	}
	return map[string]any{"threshold": threshold, "cards": cards}
}

type client struct {
	base string
	hc   *http.Client
}

func (c *client) do(method, path string, body any) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, b, nil
}

func asObject(b []byte) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

// errorFields 提取 400 响应中全部可定位错误的 field。
func errorFields(b []byte) []string {
	m := asObject(b)
	list, _ := m["errors"].([]any)
	var out []string
	for _, e := range list {
		if em, ok := e.(map[string]any); ok {
			if f, ok := em["field"].(string); ok {
				out = append(out, f)
			}
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

type check struct {
	name string
	run  func(c *client) error
}

func main() {
	url := flag.String("url", os.Getenv("APP_URL"), "被测服务的基础 URL")
	wait := flag.Duration("wait", 60*time.Second, "等待服务就绪的最长时间")
	flag.Parse()
	base := *url
	if base == "" {
		base = "http://127.0.0.1:8080"
	}
	c := &client{base: strings.TrimRight(base, "/"), hc: &http.Client{Timeout: 10 * time.Second}}

	if err := waitHealthy(c, *wait); err != nil {
		fmt.Printf("[FAIL] 服务未就绪：%v\n", err)
		os.Exit(1)
	}

	failed := 0
	for _, chk := range checks() {
		if err := chk.run(c); err != nil {
			failed++
			fmt.Printf("[FAIL] %s：%v\n", chk.name, err)
		} else {
			fmt.Printf("[PASS] %s\n", chk.name)
		}
	}
	if failed > 0 {
		fmt.Printf("HTTP 冒烟：%d 项未通过\n", failed)
		os.Exit(1)
	}
	fmt.Println("HTTP 冒烟：全部通过")
}

func waitHealthy(c *client, max time.Duration) error {
	deadline := time.Now().Add(max)
	for {
		code, _, err := c.do(http.MethodGet, "/health", nil)
		if err == nil && code == http.StatusOK {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("等待 /health 超时（%s）", max)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func checks() []check {
	return []check{
		{"健康检查 GET /health", checkHealth},
		{"值守页面 GET / 可访问", checkIndex},
		{"API 拒绝非 POST 方法", checkMethodNotAllowed},
		{"全部一致返回 CONSISTENT 与正确密钥", checkConsistent},
		{"剔除一张问题卡返回 RECOVERED、编号与密钥", checkRecovered},
		{"两张问题卡返回 CONFLICT 且不泄露密钥", checkConflict},
		{"编号重复返回可定位的 400", checkDuplicateIDs},
		{"非十六进制份额返回可定位的 400", checkBadHex},
		{"份额不等长返回可定位的 400", checkUnequalLength},
		{"门限越界返回可定位的 400", checkThresholdRange},
		{"卡片数量越界返回可定位的 400", checkCardCount},
	}
}

func checkHealth(c *client) error {
	code, body, err := c.do(http.MethodGet, "/health", nil)
	if err != nil {
		return err
	}
	if code != http.StatusOK || !strings.Contains(string(body), "ok") {
		return fmt.Errorf("code=%d body=%s", code, body)
	}
	return nil
}

func checkIndex(c *client) error {
	code, body, err := c.do(http.MethodGet, "/", nil)
	if err != nil {
		return err
	}
	if code != http.StatusOK || !strings.Contains(string(body), "恢复") {
		return fmt.Errorf("code=%d", code)
	}
	return nil
}

func checkMethodNotAllowed(c *client) error {
	code, _, err := c.do(http.MethodGet, "/api/recovery/reconstruct", nil)
	if err != nil {
		return err
	}
	if code != http.StatusMethodNotAllowed {
		return fmt.Errorf("GET /api/recovery/reconstruct 应返回 405，实际 %d", code)
	}
	return nil
}

func checkConsistent(c *client) error {
	code, body, err := c.do(http.MethodPost, "/api/recovery/reconstruct", payload(testShares(), 3))
	if err != nil {
		return err
	}
	m := asObject(body)
	if code != http.StatusOK || m["status"] != "CONSISTENT" {
		return fmt.Errorf("code=%d status=%v", code, m["status"])
	}
	if m["key"] != secretHex {
		return fmt.Errorf("密钥错误：%v", m["key"])
	}
	return nil
}

func checkRecovered(c *client) error {
	pts := testShares()
	pts[3].Y[0] ^= 0x01 // 编号 4 的卡抄错一个字节
	code, body, err := c.do(http.MethodPost, "/api/recovery/reconstruct", payload(pts, 3))
	if err != nil {
		return err
	}
	m := asObject(body)
	if code != http.StatusOK || m["status"] != "RECOVERED" {
		return fmt.Errorf("code=%d status=%v", code, m["status"])
	}
	if m["excludedCardId"] != float64(4) {
		return fmt.Errorf("问题卡编号错误：%v", m["excludedCardId"])
	}
	if m["key"] != secretHex {
		return fmt.Errorf("密钥错误：%v", m["key"])
	}
	return nil
}

func checkConflict(c *client) error {
	pts := testShares()
	pts[3].Y[0] ^= 0x01
	pts[4].Y[1] ^= 0x80
	code, body, err := c.do(http.MethodPost, "/api/recovery/reconstruct", payload(pts, 3))
	if err != nil {
		return err
	}
	m := asObject(body)
	if code != http.StatusOK || m["status"] != "CONFLICT" {
		return fmt.Errorf("code=%d status=%v", code, m["status"])
	}
	if _, leaked := m["key"]; leaked || bytes.Contains(body, []byte(secretHex)) {
		return fmt.Errorf("CONFLICT 泄露了密钥材料：%s", body)
	}
	return nil
}

func checkDuplicateIDs(c *client) error {
	p := payload(testShares(), 3)
	cards := p["cards"].([]map[string]any)
	cards[1]["id"] = cards[0]["id"]
	code, body, err := c.do(http.MethodPost, "/api/recovery/reconstruct", p)
	if err != nil {
		return err
	}
	if code != http.StatusBadRequest {
		return fmt.Errorf("应返回 400，实际 %d", code)
	}
	if !hasField(errorFields(body), "cards[1].id") {
		return fmt.Errorf("错误未定位到 cards[1].id：%s", body)
	}
	return nil
}

func checkBadHex(c *client) error {
	p := payload(testShares(), 3)
	p["cards"].([]map[string]any)[0]["share"] = "zz99"
	code, body, err := c.do(http.MethodPost, "/api/recovery/reconstruct", p)
	if err != nil {
		return err
	}
	if code != http.StatusBadRequest {
		return fmt.Errorf("应返回 400，实际 %d", code)
	}
	if !hasField(errorFields(body), "cards[0].share") {
		return fmt.Errorf("错误未定位到 cards[0].share：%s", body)
	}
	return nil
}

func checkUnequalLength(c *client) error {
	p := payload(testShares(), 3)
	cards := p["cards"].([]map[string]any)
	s := cards[2]["share"].(string)
	cards[2]["share"] = s[:len(s)-2]
	code, body, err := c.do(http.MethodPost, "/api/recovery/reconstruct", p)
	if err != nil {
		return err
	}
	if code != http.StatusBadRequest {
		return fmt.Errorf("应返回 400，实际 %d", code)
	}
	if !hasField(errorFields(body), "cards[2].share") {
		return fmt.Errorf("错误未定位到 cards[2].share：%s", body)
	}
	return nil
}

func checkThresholdRange(c *client) error {
	for _, t := range []int{1, 9} {
		code, body, err := c.do(http.MethodPost, "/api/recovery/reconstruct", payload(testShares(), t))
		if err != nil {
			return err
		}
		if code != http.StatusBadRequest {
			return fmt.Errorf("threshold=%d 应返回 400，实际 %d", t, code)
		}
		if !hasField(errorFields(body), "threshold") {
			return fmt.Errorf("threshold=%d 的错误未定位到 threshold：%s", t, body)
		}
	}
	return nil
}

func checkCardCount(c *client) error {
	code, body, err := c.do(http.MethodPost, "/api/recovery/reconstruct", payload(testShares()[:3], 2))
	if err != nil {
		return err
	}
	if code != http.StatusBadRequest {
		return fmt.Errorf("应返回 400，实际 %d", code)
	}
	if !hasField(errorFields(body), "cards") {
		return fmt.Errorf("错误未定位到 cards：%s", body)
	}
	return nil
}
