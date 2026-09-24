# syntax=docker/dockerfile:1

# ---------- 构建阶段：编译服务二进制 ----------
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/recovery-server ./cmd/server

# ---------- 运行镜像：恢复密钥合成服务 ----------
FROM alpine:3.20 AS runtime
RUN adduser -D -u 10001 appuser
COPY --from=build /out/recovery-server /usr/local/bin/recovery-server
# 容器内监听端口（宿主机端口由 docker compose 的 HOST_PORT 配置）
ENV PORT=8080
EXPOSE 8080
USER appuser
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${PORT}/health" || exit 1
ENTRYPOINT ["/usr/local/bin/recovery-server"]

# ---------- 一次性验收镜像：代码测试 + 构建检查 + HTTP 冒烟 ----------
FROM golang:1.23-alpine AS verify
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
COPY scripts ./scripts
ENV APP_URL=http://app:8080
CMD ["sh", "scripts/verify.sh"]
