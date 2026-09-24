#!/bin/sh
# 一次性验收：单元测试 → 构建检查 → HTTP 冒烟。
# 任一步骤失败即以非零码退出；全部通过以退出码 0 结束。
set -eu

APP_URL="${APP_URL:-http://127.0.0.1:8080}"

echo "[verify] 1/3 代码测试: go test ./..."
go test ./...

echo "[verify] 2/3 构建检查: go vet ./... && go build ./..."
go vet ./...
go build ./...

echo "[verify] 3/3 HTTP 冒烟: ${APP_URL}"
go run ./cmd/verify --url "${APP_URL}"

echo "[verify] 全部通过"
