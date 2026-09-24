# 离线恢复卡 · 设备恢复密钥合成服务

值守员录入 4–8 张恢复卡的唯一非零编号、门限值与等长十六进制份额。服务在
GF(2⁸)（多项式 x⁸+x⁴+x³+x+1，生成元 3）上将每张卡视为度为「门限值 − 1」
多项式上的点，以该多项式在零点 x=0 的取值作为设备恢复密钥。

判定结论：

| 结论 | 条件 | 返回 |
| --- | --- | --- |
| `CONSISTENT` | 全部份额落在同一多项式上 | 结论 + 密钥 |
| `RECOVERED` | **恰好剔除一张卡**后，其余不少于门限值的份额一致 | 结论 + 问题卡编号 + 密钥 |
| `CONFLICT` | 其他所有情况（多张卡冲突、或无法唯一确定问题卡） | 仅结论，**绝不返回密钥** |

## 目录结构

```
app/
  gf.py            GF(256) 运算（对数/指数表、Lagrange 插值）
  reconstruct.py   输入校验、一致性判定与密钥重构
  server.py        标准库 HTTP 服务（POST /api/recovery/reconstruct 等）
  healthcheck.py   容器健康探针
  static/index.html 值守员录入页面（零外部依赖、纯离线）
tests/             unittest 单元/接口/HTTP 测试（46 个）
verify.py          一次性验收：构建检查 + 代码测试 + HTTP 冒烟
Dockerfile         零 pip 依赖，python:3.11-slim
docker-compose.yml web 服务 + verify 一次性验收服务
```

## 本地运行（无需 Docker）

```bash
python3 -m app.server            # 默认 8080，可用 PORT 环境变量覆盖
# 浏览器打开 http://127.0.0.1:8080/
```

## Docker Compose 运行

宿主机端口通过 `HOST_PORT` 配置（默认 8080）：

```bash
docker compose up --build
HOST_PORT=9090 docker compose up --build      # 映射到宿主机 9090
```

服务自带容器健康检查（`/healthz`）。

## 一次性验收服务 verify

```bash
# 构建后运行验收；verify 完成构建检查、46 项测试与 HTTP 冒烟后自行退出，
# 退出码 0 表示验收通过，非 0 表示失败。
docker compose build
docker compose up --exit-code-from verify verify
docker inspect $(docker compose ps -q verify) -f '{{.State.ExitCode}}'
```

本机直接运行验收（先起服务）：

```bash
PORT=8080 python3 -m app.server &
SMOKE_URL=http://127.0.0.1:8080 python3 verify.py
```

## HTTP 接口

### `POST /api/recovery/reconstruct`

请求：

```json
{
  "cards": [11, 22, 33, 44, 55],
  "threshold": 3,
  "shares": ["01ab…", "23cd…", "45ef…", "6701…", "8923…"]
}
```

成功响应（HTTP 200）：

```json
{ "ok": true, "status": "CONSISTENT", "key": "…" }
{ "ok": true, "status": "RECOVERED", "bad_card": 33, "key": "…" }
{ "ok": true, "status": "CONFLICT" }
```

输入错误（HTTP 400），每条错误都可定位到字段与行号（从 0 开始）：

```json
{
  "ok": false,
  "errors": [
    { "field": "card", "index": 2, "message": "编号 22 与第 2 行重复…" },
    { "field": "share", "index": 3, "message": "份额长度 6 与第 1 行长度 8 不一致…" },
    { "field": "threshold", "index": null, "message": "门限值必须在 2 到 5 之间…" }
  ]
}
```

校验规则：

- 卡片数量 4–8；编号为 1–255 的非零整数且**全局唯一**；
- 门限值为 2 ≤ k ≤ 卡片数量；
- 每份份额均为十六进制字符串（`0-9a-fA-F`）、偶数长度、全部等长；
- 任何校验失败都不会进入重构，更不会返回密钥。

服务端无状态：提交新数据不会保留任何旧结论；页面在每次提交前也会清空上一次
的结论与逐行错误提示。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
