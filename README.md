# 高安全分析仪 · 离线恢复密钥合成

值守员在页面录入 **4–8 张**恢复卡的**唯一非零编号**、**门限值**与**等长十六进制份额**，
服务在 **GF(256)**（模既约多项式 x⁸+x⁴+x³+x+1，即 `0x11b`，与 AES 同域）上把每张卡视为
「门限值 − 1」阶多项式上的一个点（横坐标 = 卡编号，纵坐标 = 份额逐字节），
并以**零点值**作为设备恢复密钥（Shamir 门限方案，逐字节独立插值）。

## 判定规则

| 情形 | 状态 | 输出 |
| --- | --- | --- |
| 全部份额落在同一多项式上 | `CONSISTENT` | 恢复密钥 |
| 剔除**唯一**一张卡后，其余（不少于门限值）份额一致 | `RECOVERED` | 问题卡编号 + 恢复密钥 |
| 其他一切情况 | `CONFLICT` | **不输出任何密钥** |

安全约束：

- `CONFLICT` 响应绝不携带密钥，避免一张卡抄错后仍把错误密钥用于设备恢复；
- 门限值 = 卡片数量时没有任何冗余：任意份额组合在数学上都「一致」，
  服务只能给出 `CONSISTENT`，该配置下抄错无法被检测（请勿用于实际恢复）；
- 卡片数量 = 门限值 + 1 时，剔除任意一张后剩余份额必然「一致」，
  无法唯一定位问题卡，判 `CONFLICT`；
- 服务无状态；页面在提交新数据或修改任何输入后立即清除旧结论。

## 输入约束（违反时返回 400 与可定位错误）

- 卡片数量：4–8 张；
- 编号：1–255 的整数且互不重复（GF(256) 非零横坐标）；
- 门限值：2 至卡片数量；
- 份额：非空、偶数长度的十六进制串，各卡等长，最长 128 字节。

错误响应形如：

```json
{
  "status": "INVALID",
  "errors": [
    { "field": "cards[1].id", "message": "编号 3 与其他卡重复" },
    { "field": "cards[2].share", "message": "份额包含非十六进制字符" }
  ]
}
```

`field` 可定位到具体输入框：`threshold`、`cards`、`cards[i].id`、`cards[i].share`。

## API

### `POST /api/recovery/reconstruct`

请求：

```json
{
  "threshold": 3,
  "cards": [
    { "id": 1, "share": "9f3a…" },
    { "id": 2, "share": "04bc…" }
  ]
}
```

响应（200）：

```json
{ "status": "CONSISTENT", "key": "0011…" }
{ "status": "RECOVERED", "excludedCardId": 4, "key": "0011…" }
{ "status": "CONFLICT" }
```

输入非法时返回 400（见上）。非 POST 方法返回 405。

### `GET /health`

健康检查，返回 `{"status":"ok"}`。

### `GET /`

值守员录入页面。

## 运行（Docker）

```bash
# 宿主机端口默认 8080，可用 HOST_PORT 覆盖
docker compose up -d app                 # http://localhost:8080
HOST_PORT=9090 docker compose up -d app  # http://localhost:9090
```

容器内端口固定为 8080（可用环境变量 `PORT` 改），宿主机端口由 `HOST_PORT` 配置。
镜像内置 `HEALTHCHECK`，Compose 亦配置了 `/health` 健康检查。

## 一次性验收（verify）

`verify` 服务依次完成 **代码测试（go test）→ 构建检查（go vet + go build）→ HTTP 冒烟**，
随后自行退出，退出码 0 表示全部通过、非 0 表示存在失败项：

```bash
docker compose run --rm verify
echo $?                                   # 0 = 通过
# 或
docker compose up --exit-code-from verify verify
```

HTTP 冒烟覆盖：健康检查、页面可达、方法限制、`CONSISTENT` 密钥正确性、
`RECOVERED` 问题卡定位与密钥正确性、`CONFLICT` 不泄露密钥，以及各类非法输入的 400 可定位反馈。

## 本地开发

```bash
go test ./...                # 单元测试
go run ./cmd/server          # 启动服务（PORT 环境变量可改端口，默认 8080）
APP_URL=http://127.0.0.1:8080 sh scripts/verify.sh   # 本地跑同一套验收
```

## 目录结构

```
├── Dockerfile              # 多阶段：build / runtime（含 HEALTHCHECK）/ verify
├── docker-compose.yml      # app（HOST_PORT 可配宿主机端口）+ verify 一次性验收
├── scripts/verify.sh       # 验收入口：测试 → 构建检查 → HTTP 冒烟
├── cmd/
│   ├── server/             # 服务入口（PORT 环境变量）
│   └── verify/             # HTTP 冒烟程序
└── internal/
    ├── gf256/              # GF(2^8) 有限域运算（0x11b）
    ├── shamir/             # 插值、密钥重建与 CONSISTENT/RECOVERED/CONFLICT 判定
    └── server/             # HTTP API、输入校验、静态页面（web/ 内嵌）
```
