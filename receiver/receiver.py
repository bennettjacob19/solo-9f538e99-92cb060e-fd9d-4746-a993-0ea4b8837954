#!/usr/bin/env python3
"""本地遥测接收器：原样回显报文，可延迟回包，并提供就绪查询接口。

就绪接口（内部使用）：
    GET /readyz  ->  {"name": "A", "instance": "A-1a2b3c4d5e6f", "ready": true, ...}

- `instance` 每次进程启动都会重新生成，用来区分“同名接收器”的不同实例；
- UDP 套接字成功绑定、能够接收业务报文之后，才可能报告 ready；
- 可用 READY_DELAY 让实例启动后延迟一段时间才报告就绪（模拟重建较慢）。

延迟回包（优先级从高到低）：
1. 报文以 "DELAY:<秒>:" 开头时，按该秒数延迟（回包仍包含完整原始报文）；
2. 否则用环境变量 REPLY_DELAY（秒，默认 0）。

环境变量：
  RECEIVER_NAME  显示名（默认 receiver）
  LISTEN_PORT    业务 UDP 端口（默认 9001）
  HTTP_PORT      就绪查询 HTTP 端口（默认 9002）
  BIND_HOST      UDP 绑定地址（默认 0.0.0.0；本地多实例可绑不同回环 IP）
  HTTP_HOST      HTTP 绑定地址（默认同 BIND_HOST）
  REPLY_DELAY    默认回包延迟秒数（默认 0）
  READY_DELAY    UDP 绑定成功后再延迟多少秒才报告就绪（默认 0）
  MAX_DELAY      单条报文可指定的最大延迟（默认 60）
"""

import asyncio
import json
import os
import re
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME = os.environ.get("RECEIVER_NAME", "receiver")
PORT = int(os.environ.get("LISTEN_PORT", "9001"))
# 就绪接口默认在业务 UDP 端口 + 1，与代理的默认约定一致。
HTTP_PORT = int(os.environ.get("HTTP_PORT", str(PORT + 1)))
BIND_HOST = os.environ.get("BIND_HOST", "0.0.0.0")
HTTP_HOST = os.environ.get("HTTP_HOST", BIND_HOST)
DEFAULT_DELAY = float(os.environ.get("REPLY_DELAY", "0"))
READY_DELAY = max(0.0, float(os.environ.get("READY_DELAY", "0")))
MAX_DELAY = float(os.environ.get("MAX_DELAY", "60"))

DELAY_RE = re.compile(rb"^DELAY:([0-9]+(?:\.[0-9]+)?):")

# 每次启动都生成新的实例编号：同名接收器（服务名不变）重建后编号必然不同。
INSTANCE_ID = f"{NAME}-{uuid.uuid4().hex[:12]}"
STARTED_AT = time.time()

# 收到这个探测报文说明本实例的 UDP 端确实能收业务报文（自检，不转发）。
# 探测报文带本实例编号，只有完全一致才吞掉，不会吞掉客户端真实报文。
PROBE = b"\x00READY-PROBE:" + INSTANCE_ID.encode()

# HTTP 线程与 asyncio 线程共享的就绪状态。
_ready_lock = threading.Lock()
_ready_state = {
    "udp_bound": False,
    "udp_bound_at": None,
    "udp_verified": False,   # 自检报文已在本实例 UDP 端收到
    "ready_at": None,
    "packets_received": 0,
    "last_packet_at": None,
}
_probe_event = None  # 由事件循环创建


def _snapshot_ready():
    with _ready_lock:
        udp_bound = bool(_ready_state["udp_bound"])
        udp_verified = bool(_ready_state["udp_verified"])
        ready_at = _ready_state["ready_at"]
        ready = bool(
            udp_bound and udp_verified and ready_at is not None
            and time.monotonic() >= ready_at
        )
        if ready:
            state = "ready"
        elif udp_bound and udp_verified:
            state = "warming"  # UDP 已能收报文，但延迟就绪时间未到
        else:
            state = "binding"  # 尚未证明能收业务报文
        return {
            "name": NAME,
            "instance": INSTANCE_ID,
            "ready": ready,
            "state": state,
            "udp_bound": udp_bound,
            "udp_verified": udp_verified,
            "udp_port": PORT,
            "http_port": HTTP_PORT,
            "bind_host": BIND_HOST,
            "ready_delay": READY_DELAY,
            "packets_received": _ready_state["packets_received"],
            "last_packet_at": _ready_state["last_packet_at"],
            "pid": os.getpid(),
            "started_at": STARTED_AT,
        }


class ReadyHandler(BaseHTTPRequestHandler):
    server_version = "TelemetryReceiver/1.0"

    def _send(self, code, body):
        raw = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802 (http.server 接口)
        path = self.path.split("?", 1)[0]
        if path not in ("/readyz", "/healthz", "/"):
            self._send(404, {"error": "not found", "name": NAME, "instance": INSTANCE_ID})
            return
        self._send(200, _snapshot_ready())

    def log_message(self, fmt, *args):  # 保持容器日志干净
        pass


def start_http_server():
    """先启动 HTTP（此时 ready=false），UDP 绑定成功后才可能变为就绪。

    就绪接口起不来不应影响业务 UDP：记录错误并继续，但此实例永远无法被确认为就绪，
    代理会保留原通道（安全侧）。
    """
    try:
        server = ThreadingHTTPServer((HTTP_HOST, HTTP_PORT), ReadyHandler)
    except OSError as exc:
        print(f"[{NAME}] 就绪接口绑定失败 {HTTP_HOST}:{HTTP_PORT}: {exc}"
              f"（业务 UDP 继续运行，但不会报告就绪）", flush=True)
        return None
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name="ready-http", daemon=True)
    thread.start()
    print(f"[{NAME}] 就绪接口 http://{HTTP_HOST}:{HTTP_PORT}/readyz，实例 {INSTANCE_ID}",
          flush=True)
    return server


class ReceiverProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if data == PROBE:
            # 就绪自检：确认这个 UDP 端能收到业务报文（只吞掉完全一致的探测报文）。
            with _ready_lock:
                _ready_state["udp_verified"] = True
            if _probe_event is not None:
                _probe_event.set()
            return
        with _ready_lock:
            _ready_state["packets_received"] += 1
            _ready_state["last_packet_at"] = time.time()
        delay = DEFAULT_DELAY
        m = DELAY_RE.match(data)
        if m:
            delay = min(float(m.group(1)), MAX_DELAY)
        print(f"[{NAME}] 收到 {len(data)}B 来自 {addr[0]}:{addr[1]}，{delay}s 后回包", flush=True)
        asyncio.get_running_loop().call_later(delay, self._reply, data, addr)

    def _reply(self, data, addr):
        try:
            self.transport.sendto(data, addr)  # 原样回显
            print(f"[{NAME}] 已回包 {len(data)}B 到 {addr[0]}:{addr[1]}", flush=True)
        except Exception as exc:
            print(f"[{NAME}] 回包失败: {exc}", flush=True)


async def _verify_udp(loop):
    """向自己的 UDP 端口发一个自检报文，收到才算真的能收业务报文。"""
    global _probe_event
    _probe_event = asyncio.Event()
    target_host = BIND_HOST
    if target_host in ("0.0.0.0", "", "::"):
        target_host = "127.0.0.1"
    for _ in range(10):
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.sendto(PROBE, (target_host, PORT))
        except OSError as exc:
            print(f"[{NAME}] 就绪自检发送失败: {exc}", flush=True)
        finally:
            probe.close()
        try:
            await asyncio.wait_for(_probe_event.wait(), 0.5)
            return True
        except asyncio.TimeoutError:
            _probe_event.clear()
    return False


async def main():
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(
        lambda: ReceiverProtocol(), local_addr=(BIND_HOST, PORT)
    )
    verified = await _verify_udp(loop)
    with _ready_lock:
        _ready_state["udp_bound"] = True
        _ready_state["udp_bound_at"] = time.monotonic()
        _ready_state["udp_verified"] = verified
        _ready_state["ready_at"] = time.monotonic() + READY_DELAY
    if not verified:
        print(f"[{NAME}] 警告：UDP 就绪自检未通过，不会报告就绪", flush=True)
    print(
        f"[{NAME}] UDP 监听 {BIND_HOST}:{PORT}，实例 {INSTANCE_ID}，"
        f"默认回包延迟 {DEFAULT_DELAY}s，就绪延迟 {READY_DELAY}s",
        flush=True,
    )
    if READY_DELAY:
        loop.call_later(READY_DELAY, lambda: print(
            f"[{NAME}] 已就绪（实例 {INSTANCE_ID}）", flush=True))
    await asyncio.Event().wait()


if __name__ == "__main__":
    start_http_server()
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
