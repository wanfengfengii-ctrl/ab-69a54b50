// Package server 提供恢复密钥合成的 HTTP API 与值守员页面。
package server

import (
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strings"

	"recovery/internal/shamir"
)

//go:embed web
var webFS embed.FS

const (
	minCards      = 4
	maxCards      = 8
	minThreshold  = 2
	minCardID     = 1
	maxCardID     = 255
	maxShareBytes = 128
	maxBodyBytes  = 1 << 20
)

// New 返回服务的根 HTTP 处理器（API + 静态页面 + 健康检查）。
func New() http.Handler {
	static, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("POST /api/recovery/reconstruct", handleReconstruct)
	mux.HandleFunc("GET /api/recovery/reconstruct", handleMethodNotAllowed)
	mux.Handle("GET /", http.FileServerFS(static))
	return secureHeaders(mux)
}

// secureHeaders 设置安全响应头；no-store 确保密钥材料不被缓存。
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---- 请求 / 响应模型 ----

type reconstructRequest struct {
	Threshold json.Number `json:"threshold"`
	Cards     []cardInput `json:"cards"`
}

type cardInput struct {
	ID    json.Number `json:"id"`
	Share string      `json:"share"`
}

// fieldError 是可定位到具体输入框的校验错误。
// Field 形如 "threshold"、"cards"、"cards[2].id"、"cards[1].share"。
type fieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// handleMethodNotAllowed 明确拒绝 API 路径上的 GET，避免落入静态文件服务。
// 其他方法由 ServeMux 自动返回 405。
func handleMethodNotAllowed(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Allow", http.MethodPost)
	writeInvalid(w, http.StatusMethodNotAllowed, []fieldError{
		{Field: "", Message: "该接口仅支持 POST"},
	})
}

func handleReconstruct(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var req reconstructRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeInvalid(w, http.StatusBadRequest, []fieldError{
			{Field: "", Message: "请求体必须是合法的 JSON（threshold 为数字，cards 为数组）"},
		})
		return
	}

	points, threshold, errs := validateReconstruct(&req)
	if len(errs) > 0 {
		writeInvalid(w, http.StatusBadRequest, errs)
		return
	}

	res := shamir.Analyze(points, threshold)
	switch res.Status {
	case shamir.StatusConsistent:
		writeJSON(w, http.StatusOK, map[string]any{
			"status": string(res.Status),
			"key":    hex.EncodeToString(res.Key),
		})
	case shamir.StatusRecovered:
		writeJSON(w, http.StatusOK, map[string]any{
			"status":         string(res.Status),
			"excludedCardId": int(res.Excluded),
			"key":            hex.EncodeToString(res.Key),
		})
	default:
		// CONFLICT：绝不输出密钥，避免错误密钥被用于设备恢复。
		writeJSON(w, http.StatusOK, map[string]any{
			"status": string(shamir.StatusConflict),
		})
	}
}

// validateReconstruct 校验全部输入；全部合法时返回份额点与门限值，
// 否则返回可定位到具体输入框的错误列表。
func validateReconstruct(req *reconstructRequest) ([]shamir.Point, int, []fieldError) {
	var errs []fieldError
	add := func(field, format string, args ...any) {
		errs = append(errs, fieldError{Field: field, Message: fmt.Sprintf(format, args...)})
	}

	n := len(req.Cards)
	if n < minCards || n > maxCards {
		add("cards", "卡片数量必须在 %d–%d 张之间（当前 %d 张）", minCards, maxCards, n)
	}

	threshold := 0
	switch t, err := req.Threshold.Int64(); {
	case req.Threshold == "":
		add("threshold", "门限值必填")
	case err != nil:
		add("threshold", "门限值必须是整数")
	case t < minThreshold:
		add("threshold", "门限值至少为 %d", minThreshold)
	case n >= minCards && n <= maxCards && t > int64(n):
		add("threshold", "门限值不能大于卡片数量（当前 %d 张）", n)
	default:
		threshold = int(t)
	}

	ids := make([]int64, n)
	shares := make([][]byte, n)
	seen := map[int64][]int{}
	for i := range req.Cards {
		c := &req.Cards[i]
		idField := fmt.Sprintf("cards[%d].id", i)
		shareField := fmt.Sprintf("cards[%d].share", i)

		switch id, err := c.ID.Int64(); {
		case c.ID == "":
			add(idField, "编号必填")
		case err != nil:
			add(idField, "编号必须是整数")
		case id < minCardID || id > maxCardID:
			add(idField, "编号必须在 %d–%d 之间（非零，作为 GF(256) 横坐标）", minCardID, maxCardID)
		default:
			ids[i] = id
			seen[id] = append(seen[id], i)
		}

		s := strings.TrimSpace(c.Share)
		switch {
		case s == "":
			add(shareField, "份额必填")
		case len(s)%2 != 0:
			add(shareField, "份额必须为偶数个十六进制字符（当前 %d 个字符）", len(s))
		case !isHex(s):
			add(shareField, "份额包含非十六进制字符")
		default:
			b, _ := hex.DecodeString(s)
			if len(b) > maxShareBytes {
				add(shareField, "份额过长：最多 %d 字节（当前 %d 字节）", maxShareBytes, len(b))
			} else {
				shares[i] = b
			}
		}
	}

	// 编号唯一性：标记所有涉及重复的输入框。
	for id, idxs := range seen {
		if len(idxs) < 2 {
			continue
		}
		for _, i := range idxs {
			add(fmt.Sprintf("cards[%d].id", i), "编号 %d 与其他卡重复", id)
		}
	}

	// 等长检查：以出现次数最多的长度为基准，标记不一致的份额。
	lengths := map[int]int{}
	for _, b := range shares {
		if b != nil {
			lengths[len(b)]++
		}
	}
	if len(lengths) > 1 {
		base, baseCount := 0, -1
		for l, c := range lengths {
			if c > baseCount {
				base, baseCount = l, c
			}
		}
		for i, b := range shares {
			if b != nil && len(b) != base {
				add(fmt.Sprintf("cards[%d].share", i), "份额长度需一致：应为 %d 字节，本卡 %d 字节", base, len(b))
			}
		}
	}

	if len(errs) > 0 {
		return nil, 0, errs
	}
	points := make([]shamir.Point, n)
	for i := range req.Cards {
		points[i] = shamir.Point{X: byte(ids[i]), Y: shares[i]}
	}
	return points, threshold, nil
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return len(s) > 0
}

func writeInvalid(w http.ResponseWriter, code int, errs []fieldError) {
	writeJSON(w, code, map[string]any{
		"status": "INVALID",
		"errors": errs,
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
