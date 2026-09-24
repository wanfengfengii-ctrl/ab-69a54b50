#!/usr/bin/env python3
"""One-shot acceptance service for the recovery-card project.

Stages (any failure => non-zero exit code):
  1. build check  - byte-compile every Python source and import the package
  2. code tests   - run the unittest suite
  3. HTTP smoke   - exercise the running service end to end:
                      health probe, static page, CONSISTENT, RECOVERED,
                      CONFLICT (key must be absent), and a locatable 400

Designed to run either inside the compose "verify" container
(SMOKE_URL=http://web:8080) or directly on a developer machine
(SMOKE_URL=http://127.0.0.1:<port>).
"""

from __future__ import annotations

import json
import os
import py_compile
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SMOKE_URL = os.environ.get("SMOKE_URL", "http://127.0.0.1:8080").rstrip("/")

# ANSI when attached to a TTY; plain text otherwise.
def _paint(code: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text


def ok(msg: str) -> None:
    print(_paint("32", "  [PASS] ") + msg, flush=True)


def fail(msg: str) -> None:
    print(_paint("31", "  [FAIL] ") + msg, flush=True)


def stage(title: str) -> None:
    print(_paint("1;36", f"\n== {title} =="), flush=True)


failures: list[str] = []


# ---------------------------------------------------------------------------
# Stage 1: build check
# ---------------------------------------------------------------------------
def build_check() -> None:
    stage("1/3 构建检查（compileall / import / 交付物）")
    required = [
        ROOT / "app" / "server.py",
        ROOT / "app" / "gf.py",
        ROOT / "app" / "reconstruct.py",
        ROOT / "app" / "static" / "index.html",
        ROOT / "Dockerfile",
        ROOT / "docker-compose.yml",
    ]
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        failures.append("缺少交付文件: " + ", ".join(missing))
        for m in missing:
            fail(f"缺少 {m}")
    else:
        ok("全部交付文件存在（应用/页面/Dockerfile/compose）")

    compile_failed: list[str] = []
    for path in list((ROOT / "app").rglob("*.py")) + list(
        (ROOT / "tests").rglob("*.py")
    ) + [ROOT / "verify.py"]:
        try:
            py_compile.compile(str(path), doraise=True, quiet=2)
        except py_compile.PyCompileError as exc:
            compile_failed.append(f"{path}: {exc.msg}")
    if compile_failed:
        failures.append("字节码编译失败")
        for m in compile_failed:
            fail(m)
    else:
        ok("全部 Python 源码通过字节码编译")

    try:
        compile_proc = subprocess.run(
            [sys.executable, "-c", "import app.server, app.gf, app.reconstruct"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if compile_proc.returncode != 0:
            failures.append("应用模块无法导入")
            fail(compile_proc.stderr.strip())
        else:
            ok("应用模块导入成功，无第三方依赖")
    except (OSError, subprocess.TimeoutExpired) as exc:
        failures.append(f"导入检查异常: {exc}")
        fail(str(exc))


# ---------------------------------------------------------------------------
# Stage 2: code tests
# ---------------------------------------------------------------------------
def run_tests() -> None:
    stage("2/3 代码测试（unittest）")
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=ROOT,
        timeout=180,
    )
    if proc.returncode != 0:
        failures.append("单元/接口测试未全部通过")
        fail("unittest 返回非零退出码")
    else:
        ok("unittest 全部通过")


# ---------------------------------------------------------------------------
# Stage 3: HTTP smoke
# ---------------------------------------------------------------------------
def _request(method: str, path: str, body=None, timeout: float = 5.0):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        SMOKE_URL + path, data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read()
        return e.code, json.loads(raw) if raw else {}


def _wait_for_service(deadline_seconds: float = 30.0) -> bool:
    print(f"  等待服务就绪：{SMOKE_URL} …", flush=True)
    deadline = time.time() + deadline_seconds
    while time.time() < deadline:
        try:
            status, _ = _request("GET", "/healthz", timeout=2)
            if status == 200:
                return True
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(0.5)
    return False


def _honest_shares(cards, threshold, key_hex: str) -> list[str]:
    """Generate deterministic honest shares using the project's own GF math."""
    sys.path.insert(0, str(ROOT))
    from app import gf  # local import keeps stage ordering obvious

    key = bytes.fromhex(key_hex)
    out = [bytearray() for _ in cards]
    for pos, secret in enumerate(key):
        # Deterministic non-constant coefficients (never all zero).
        coeffs = [secret] + [
            gf.mul(secret ^ (pos + 1) * (j + 7), 1 + j) ^ 0x5A
            for j in range(threshold - 1)
        ]
        # Guarantee the polynomial actually has degree threshold-1.
        if coeffs[-1] == 0:
            coeffs[-1] = 1
        for i, x in enumerate(cards):
            out[i].append(gf.poly_eval(coeffs, x))
    return [b.hex() for b in out]


def smoke() -> None:
    stage("3/3 HTTP 冒烟测试")
    if not _wait_for_service():
        failures.append(f"服务在 {SMOKE_URL} 不可达")
        fail("健康检查在超时时间内未通过")
        return
    ok("GET /healthz 返回 200")

    try:
        with urllib.request.urlopen(SMOKE_URL + "/", timeout=5) as resp:
            page = resp.read().decode("utf-8", "replace")
        if resp.status == 200 and "/api/recovery/reconstruct" in page:
            ok("GET / 返回值守员录入页面")
        else:
            failures.append("首页内容异常")
            fail("首页缺少接口引用")
    except (urllib.error.URLError, OSError) as exc:
        failures.append(f"首页请求失败: {exc}")
        fail(str(exc))
        return

    key_hex = "0123456789abcdef"
    cards = [11, 22, 33, 44, 55]
    threshold = 3
    shares = _honest_shares(cards, threshold, key_hex)

    status, data = _request(
        "POST", "/api/recovery/reconstruct",
        {"cards": cards, "threshold": threshold, "shares": shares},
    )
    if status == 200 and data.get("status") == "CONSISTENT" \
            and data.get("key") == key_hex:
        ok("CONSISTENT：全部诚实份额恢复出正确密钥")
    else:
        failures.append("CONSISTENT 冒烟失败")
        fail(f"status={status} body={data}")

    recovered = list(shares)
    recovered[2] = "ff" * (len(key_hex) // 2)
    status, data = _request(
        "POST", "/api/recovery/reconstruct",
        {"cards": cards, "threshold": threshold, "shares": recovered},
    )
    if (
        status == 200
        and data.get("status") == "RECOVERED"
        and data.get("bad_card") == cards[2]
        and data.get("key") == key_hex
    ):
        ok("RECOVERED：定位问题卡 33 且密钥正确")
    else:
        failures.append("RECOVERED 冒烟失败")
        fail(f"status={status} body={data}")

    conflict = list(shares)
    conflict[0] = "00" * (len(key_hex) // 2)
    conflict[3] = "ff" * (len(key_hex) // 2)
    status, data = _request(
        "POST", "/api/recovery/reconstruct",
        {"cards": cards, "threshold": threshold, "shares": conflict},
    )
    if status == 200 and data.get("status") == "CONFLICT" and "key" not in data:
        ok("CONFLICT：冲突时拒绝输出且不泄露密钥")
    else:
        failures.append("CONFLICT 冒烟失败（可能泄露密钥）")
        fail(f"status={status} body={data}")

    status, data = _request(
        "POST", "/api/recovery/reconstruct",
        {"cards": [1, 2, 2, 4], "threshold": 2, "shares": ["ab"] * 4},
    )
    locatable = (
        status == 400
        and any(
            e.get("field") == "card" and e.get("index") == 2
            for e in data.get("errors", [])
        )
    )
    if locatable:
        ok("输入校验：重复编号返回带行号的 400")
    else:
        failures.append("可定位输入反馈冒烟失败")
        fail(f"status={status} body={data}")


def main() -> int:
    print(_paint("1", "恢复卡服务 · 一次性验收 (verify)"))
    print(f"项目目录 : {ROOT}")
    print(f"冒烟目标 : {SMOKE_URL}")
    build_check()
    run_tests()
    smoke()

    print(_paint("1;36", "\n== 验收结论 =="))
    if failures:
        for f in failures:
            fail(f)
        print(_paint("1;31", f"验收未通过：{len(failures)} 项失败"))
        return 1
    print(_paint("1;32", "验收通过：构建检查、代码测试、HTTP 冒烟全部成功"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
