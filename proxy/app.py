#!/usr/bin/env python3
"""遥测 UDP 代理 + 操作网页（接收器同名换址自动改绑）。

核心行为：
- 按客户端 IP:端口建立会话；会话在建立时固定接收器名（A/B），
  网页切换 A/B 只影响之后的新会话，旧会话保留会话编号继续走原接收器；
- 每个接收器由一个后台解析器共享查询 DNS：解析结果每次只采用一个 IPv4，
  解析失败保留上一次成功地址并自动重试；
- 会话的上游通道是一个已 connect 到“当前上游 IP”的独立 UDP 套接字。
  同一接收器解析出的 IPv4 变化时，为该接收器名下的活动会话做自动改绑：
    1. 先建好指向候选 IP 的新 UDP 通道（准备）；
    2. 从候选 IP 的接收器就绪接口确认“同名实例就绪”，并记住实例编号；
    3. 确认 DNS 没有再次换址、且接管前仍是指定实例，才在原通道上完成接管；
    4. 任何一步失败都保留原通道照常收发，按退避间隔自动重试。
- 等待解析 / 确认就绪期间，原通道继续发送与接收；
- 接管后旧通道标记退役并保留观察期（RETIRED_LINGER），迟到的回包一律丢弃；
  已发送报文绝不重发；
- 迟到的改绑结果只在会话语义仍有效时生效，绝不会恢复已过期的会话；
- 会话编号在改绑前后保持不变；
- 就绪接口信息、DNS 解析状态、实际上游 IP、改绑失败原因都在网页可见。

就绪接口约定（接收器内部 HTTP）：
    GET /readyz -> {"name": "<接收器名>", "instance": "<每次启动唯一>",
                    "ready": true, ...}
"""

import asyncio
import http.client
import ipaddress
import json
import os
import socket
import sqlite3
import threading
import time

from flask import Flask, flash, jsonify, redirect, render_template, request, url_for

# ---------------- 配置 ----------------
UDP_LISTEN_HOST = os.environ.get("UDP_LISTEN_HOST", "0.0.0.0")
UDP_LISTEN_PORT = int(os.environ.get("UDP_LISTEN_PORT", "9000"))
HTTP_HOST = os.environ.get("HTTP_HOST", "0.0.0.0")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))
DB_PATH = os.environ.get(
    "DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy.db")
)
SESSION_IDLE_TIMEOUT = float(os.environ.get("SESSION_IDLE_TIMEOUT", "5"))
UPSTREAM_PORT_MIN = int(os.environ.get("UPSTREAM_PORT_MIN", "20000"))
UPSTREAM_PORT_MAX = int(os.environ.get("UPSTREAM_PORT_MAX", "29999"))
# 上游端口关闭后的冷却时间：冷却期内不再分配该端口，
# 保证旧会话迟到的回包不会被复用同端口的新会话收到。应大于接收器最大回包延迟。
UPSTREAM_PORT_COOLDOWN = float(os.environ.get("UPSTREAM_PORT_COOLDOWN", "30"))
LOG_KEEP = int(os.environ.get("LOG_KEEP", "1000"))
PENDING_MAX = int(os.environ.get("PENDING_MAX", "200"))

# 每个接收器的后台 DNS 查询间隔（所有活动会话共用一次查询结果）。
DNS_POLL_INTERVAL = float(os.environ.get("DNS_POLL_INTERVAL", "2"))
DNS_TIMEOUT = float(os.environ.get("DNS_TIMEOUT", "3"))
# 可选：本地模拟 DNS 更新的 hosts 格式文件（name ip ...）。留空走系统 DNS。
# 文件在每次后台查询时重新读取，因此改文件即可模拟“服务名不变、IPv4 变化”。
RESOLVER_HOSTS_FILE = os.environ.get("RESOLVER_HOSTS_FILE", "").strip()

# 改绑失败后的自动重试退避（秒）。
REBIND_RETRY_MIN = float(os.environ.get("REBIND_RETRY_MIN", "1"))
REBIND_RETRY_MAX = float(os.environ.get("REBIND_RETRY_MAX", "5"))
# 新建会话解析失败 / 通道准备失败后的自动重试退避（秒）。
OPEN_RETRY_MIN = float(os.environ.get("OPEN_RETRY_MIN", "0.5"))
OPEN_RETRY_MAX = float(os.environ.get("OPEN_RETRY_MAX", "3"))
# 就绪接口查询超时（秒）。
READY_TIMEOUT = float(os.environ.get("READY_TIMEOUT", "1.5"))
# 准备完成到接管之间的稳定观察窗口（秒）。窗口内 DNS 再换址或实例变化则作废本次改绑；
# 0 表示接管前立即再校验一次（事件循环内不插入等待）。
REBIND_HOLD = max(0.0, float(os.environ.get("REBIND_HOLD", "1")))
# 改绑接管后旧通道的保留观察时长（秒）：保持套接字打开以便接收并丢弃迟到回包，
# 到期后关闭并让端口进入冷却。应不小于接收器最大回包延迟。0 表示直接关闭。
RETIRED_LINGER = max(0.0, float(os.environ.get("RETIRED_LINGER", "10")))


def _receiver_def(name):
    host = os.environ.get(f"RECEIVER_{name}_HOST", "127.0.0.1")
    port = int(os.environ.get(f"RECEIVER_{name}_PORT", "9001"))
    # 默认就绪接口在业务 UDP 端口 + 1；显式设为 0 可关闭就绪校验。
    ready_port = int(os.environ.get(f"RECEIVER_{name}_READY_PORT", str(port + 1)))
    return {"host": host, "port": port, "ready_port": ready_port}


RECEIVER_DEFS = {name: _receiver_def(name) for name in ("A", "B")}
DEFAULT_TARGET = os.environ.get("DEFAULT_TARGET", "A")


def fmt_addr(addr):
    return f"{addr[0]}:{addr[1]}"


def preview(data: bytes) -> str:
    """报文内容展示：可打印文本原样显示，否则用 hex。"""
    try:
        text = data.decode("utf-8")
        if all(ch.isprintable() or ch in "\r\n\t" for ch in text):
            return text if len(text) <= 200 else text[:200] + "…"
    except UnicodeDecodeError:
        pass
    hexed = data.hex()
    return "hex:" + (hexed if len(hexed) <= 200 else hexed[:200] + "…")


def fmt_ts(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts)) + f".{int((ts % 1) * 1000):03d}"


def fmt_ts_or_none(ts):
    return fmt_ts(ts) if ts else None


# ---------------- SQLite：目标持久化 + 报文日志 ----------------
class Store:
    """线程安全的 SQLite 存取。目标(target)落库，重启后保留。"""

    def __init__(self, path):
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS message_log (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   ts REAL NOT NULL,
                   client TEXT NOT NULL DEFAULT '',
                   session_id INTEGER NOT NULL DEFAULT 0,
                   direction TEXT NOT NULL,
                   receiver TEXT NOT NULL DEFAULT '',
                   upstream TEXT NOT NULL DEFAULT '',
                   instance TEXT NOT NULL DEFAULT '',
                   payload TEXT NOT NULL DEFAULT '',
                   note TEXT NOT NULL DEFAULT '')"""
        )
        # 兼容旧库：补充新增列。
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(message_log)")}
        for col in ("upstream", "instance"):
            if col not in cols:
                self._conn.execute(
                    f"ALTER TABLE message_log ADD COLUMN {col} TEXT NOT NULL DEFAULT ''"
                )
        self._conn.commit()
        row = self._conn.execute("SELECT value FROM settings WHERE key='target'").fetchone()
        if row and row[0] in RECEIVER_DEFS:
            self._target = row[0]
        else:
            self._target = (
                DEFAULT_TARGET if DEFAULT_TARGET in RECEIVER_DEFS else sorted(RECEIVER_DEFS)[0]
            )
            self._conn.execute(
                "INSERT OR REPLACE INTO settings(key,value) VALUES('target',?)", (self._target,)
            )
            self._conn.commit()
        self._inserts = 0

    def get_target(self):
        with self._lock:
            return self._target

    def set_target(self, target):
        """先持久化，成功后才切换内存中的当前目标；失败则抛异常并保留原目标。"""
        if target not in RECEIVER_DEFS:
            raise ValueError(f"未知接收器: {target!r}")
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO settings(key,value) VALUES('target',?)", (target,)
            )
            self._conn.commit()
            self._target = target

    def log(self, direction, client="", session_id=0, receiver="", payload="", note="",
            upstream="", instance=""):
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO message_log"
                    "(ts,client,session_id,direction,receiver,upstream,instance,payload,note)"
                    " VALUES(?,?,?,?,?,?,?,?,?)",
                    (time.time(), client, session_id, direction, receiver, upstream,
                     instance, payload, note),
                )
                self._conn.commit()
                self._inserts += 1
                if self._inserts % 200 == 0:
                    self._conn.execute(
                        "DELETE FROM message_log WHERE id < "
                        "(SELECT COALESCE(MIN(id),0) FROM "
                        "(SELECT id FROM message_log ORDER BY id DESC LIMIT ?))",
                        (LOG_KEEP,),
                    )
                    self._conn.commit()
        except sqlite3.Error:
            pass  # 日志失败绝不影响转发

    def recent_messages(self, limit=100):
        with self._lock:
            rows = self._conn.execute(
                "SELECT id,ts,client,session_id,direction,receiver,upstream,instance,payload,note "
                "FROM message_log ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        cols = ("id", "ts", "client", "session_id", "direction", "receiver", "upstream",
                "instance", "payload", "note")
        return [dict(zip(cols, r)) for r in rows]

    def latest_client_record(self, client):
        """该客户端最近一条发往接收器的记录：会话编号、接收器、实际上游。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT session_id,receiver,upstream,instance FROM message_log "
                "WHERE client=? AND direction='c2r' ORDER BY id DESC LIMIT 1",
                (client,),
            ).fetchone()
        if not row:
            return None
        return {"session_id": row[0], "receiver": row[1], "upstream": row[2],
                "instance": row[3]}


# ---------------- 上游端口分配（带冷却期） ----------------
class PortAllocator:
    """显式管理上游本地端口：关闭后冷却期内不再分配，
    确保旧会话迟到的回包不会被复用同端口的新会话收到。"""

    def __init__(self, low, high, cooldown):
        self.low, self.high, self.cooldown = low, high, cooldown
        self._next = low
        self._in_use = set()
        self._closed = {}  # port -> 关闭时刻(monotonic)
        self._lock = threading.Lock()

    def allocate(self):
        with self._lock:
            now = time.monotonic()
            for _ in range(self.high - self.low + 1):
                port = self._next
                self._next += 1
                if self._next > self.high:
                    self._next = self.low
                if port in self._in_use:
                    continue
                closed_at = self._closed.get(port)
                if closed_at is not None and now - closed_at < self.cooldown:
                    continue
                self._in_use.add(port)
                self._closed.pop(port, None)
                return port
        raise RuntimeError("上游 UDP 端口耗尽")

    def release(self, port):
        with self._lock:
            self._in_use.discard(port)
            self._closed[port] = time.monotonic()

    def discard(self, port):
        """分配后绑定失败：不进入冷却，直接可用。"""
        with self._lock:
            self._in_use.discard(port)


# ---------------- DNS：每个接收器一个后台解析器 ----------------
def _load_override_hosts(path, host):
    """读取 hosts 格式覆盖文件。

    返回 (IPv4 列表, 是否可读)；文件可读但未命中该名字时列表为空
    （视为 NXDOMAIN，而不是回退到系统 DNS）。
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return [], False
    wanted = host.lower().rstrip(".")
    found = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        names = [p.lower().rstrip(".") for p in parts[1:]]
        if wanted not in names:
            continue
        try:
            ip = str(ipaddress.IPv4Address(parts[0]))
        except ipaddress.AddressValueError:
            continue
        if ip not in found:
            found.append(ip)
    return found, True


def resolve_ipv4(host, port):
    """阻塞解析，返回 (IPv4 列表, 错误)。只保留 IPv4，去重并保持 DNS 顺序。"""
    try:
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            if literal.version != 4:
                return [], f"{host} 不是 IPv4 地址"
            return [str(literal)], None
        if RESOLVER_HOSTS_FILE:
            override, readable = _load_override_hosts(RESOLVER_HOSTS_FILE, host)
            if not readable:
                return [], f"本地 DNS 覆盖文件不可读：{RESOLVER_HOSTS_FILE}"
            if not override:
                return [], f"{host} 未被本地 DNS 覆盖文件解析（NXDOMAIN）"
            return override, None
        infos = socket.getaddrinfo(host, port, family=socket.AF_INET,
                                   type=socket.SOCK_DGRAM)
        ips = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        if not ips:
            return [], "DNS 未返回 IPv4 地址"
        return ips, None
    except Exception as exc:  # socket.gaierror 等
        return [], f"{type(exc).__name__}: {exc}"


def check_ready_sync(ip, ready_port, timeout):
    """查询候选 IP 的接收器就绪接口（阻塞，线程内调用）。"""
    conn = http.client.HTTPConnection(ip, ready_port, timeout=timeout)
    try:
        conn.request("GET", "/readyz", headers={"Accept": "application/json",
                                                "Connection": "close"})
        resp = conn.getresponse()
        raw = resp.read(65536)
        status = resp.status
    finally:
        conn.close()
    if status != 200:
        raise RuntimeError(f"HTTP {status}")
    body = json.loads(raw.decode("utf-8"))
    if not isinstance(body, dict):
        raise RuntimeError("就绪接口返回格式错误")
    return body


class ReceiverGroup:
    """一个接收器名（A/B）共享的后台 DNS 状态与最近一次就绪信息。"""

    def __init__(self, name, host, port, ready_port):
        self.name = name
        self.host = host
        self.port = port
        self.ready_port = ready_port
        self._lock = threading.Lock()
        self.current_ip = None
        self.generation = 0
        self.resolve_error = None
        self.last_resolved_at = None
        self.last_resolve_attempt_at = None
        self.last_ready = None  # {ip, instance, ready, state, name, checked_at, error}

    def apply_resolution(self, ips, error):
        """应用一次解析结果。返回 (变化的旧 IP, 新 IP) 或 None。"""
        with self._lock:
            self.last_resolve_attempt_at = time.time()
            if error:
                self.resolve_error = error
                return None
            self.resolve_error = None
            self.last_resolved_at = time.time()
            # 只采用一个 IPv4：当前地址仍在结果里就保持不变，避免无谓抖动；
            # 否则采用 DNS 返回的第一个地址（保持解析顺序）。
            new_ip = self.current_ip if self.current_ip in ips else ips[0]
            if new_ip == self.current_ip:
                return None
            old_ip = self.current_ip
            self.current_ip = new_ip
            self.generation += 1
            return old_ip, new_ip

    def set_ready_info(self, info):
        with self._lock:
            self.last_ready = dict(info)

    def snapshot(self):
        with self._lock:
            return {
                "name": self.name,
                "host": self.host,
                "port": self.port,
                "ready_port": self.ready_port,
                "current_ip": self.current_ip,
                "generation": self.generation,
                "resolve_error": self.resolve_error,
                "last_resolved": fmt_ts_or_none(self.last_resolved_at),
                "last_resolve_attempt": fmt_ts_or_none(self.last_resolve_attempt_at),
                "ready": dict(self.last_ready) if self.last_ready else None,
            }


class RebindAbort(Exception):
    """改绑准备失败：保留原通道并重试。"""


# ---------------- 会话与转发 ----------------
class Session:
    __slots__ = (
        "id", "client_addr", "receiver_name", "upstream_ip", "upstream_port",
        "instance", "transport", "proto", "state", "closed", "created", "last_activity",
        "pending", "open_error", "rebind_task", "rebind_state", "rebind_reason",
        "rebind_error", "last_rebind_error", "last_rebind_error_at",
        "rebind_attempts", "rebind_started_at", "last_rebind_at",
    )

    def __init__(self, sid, client_addr, receiver_name):
        self.id = sid
        self.client_addr = client_addr
        self.receiver_name = receiver_name
        self.upstream_ip = None
        self.upstream_port = None
        self.instance = ""
        self.transport = None
        self.proto = None
        self.state = "opening"  # opening -> open -> closed
        self.closed = False
        self.created = time.monotonic()
        self.last_activity = self.created
        self.pending = []
        self.open_error = None
        self.rebind_task = None
        self.rebind_state = "idle"
        self.rebind_reason = ""
        self.rebind_error = None
        self.last_rebind_error = None
        self.last_rebind_error_at = None
        self.rebind_attempts = 0
        self.rebind_started_at = None
        self.last_rebind_at = None


class ClientProtocol(asyncio.DatagramProtocol):
    """面向遥测终端的 UDP 端。"""

    def __init__(self, state):
        self.state = state

    def datagram_received(self, data, addr):
        self.state.on_client_datagram(data, addr)

    def error_received(self, exc):
        pass


class UpstreamProtocol(asyncio.DatagramProtocol):
    """每个会话一条、已 connect 到其接收器的上游 UDP 端。
    只有该会话对应接收器的回包会到达这里。退役后到达的回包一律丢弃。"""

    def __init__(self, state):
        self.state = state
        self.session = None
        self.retired = False
        self.retired_at = None

    def datagram_received(self, data, addr):
        if self.retired:
            self.state.on_retired_datagram(self, data, addr)
            return
        sess = self.session
        if sess is not None:
            self.state.on_upstream_datagram(sess, data)

    def error_received(self, exc):
        pass  # 如对端 ICMP 不可达，忽略


class ProxyState:
    def __init__(self, store):
        self.store = store
        self.loop = None
        self.client_transport = None
        self.group_lock = threading.RLock()
        self.sessions = {}  # client_addr -> Session（仅事件循环线程修改）
        self.lock = threading.RLock()
        self.next_session_id = 1
        self.ports = PortAllocator(UPSTREAM_PORT_MIN, UPSTREAM_PORT_MAX, UPSTREAM_PORT_COOLDOWN)
        self.groups = {
            name: ReceiverGroup(name, d["host"], d["port"], d["ready_port"])
            for name, d in RECEIVER_DEFS.items()
        }
        # 已关闭会话的最终快照（网页试传在会话过期后仍能看到编号/改绑失败原因）。
        self.recent_sessions = {}
        self.recent_limit = 200
        self._last_dns_error = {}

    async def start(self):
        transport, _ = await self.loop.create_datagram_endpoint(
            lambda: ClientProtocol(self),
            local_addr=(UDP_LISTEN_HOST, UDP_LISTEN_PORT),
        )
        self.client_transport = transport
        self.loop.create_task(self._sweeper())
        for group in self.groups.values():
            self.loop.create_task(self._resolver_loop(group))
        print(f"[proxy] 客户端 UDP 监听 {UDP_LISTEN_HOST}:{UDP_LISTEN_PORT}", flush=True)
        print(f"[proxy] 空闲会话超时 {SESSION_IDLE_TIMEOUT}s，当前目标 {self.store.get_target()}",
              flush=True)
        for name, group in self.groups.items():
            mode = "本地 hosts 覆盖" if RESOLVER_HOSTS_FILE else "系统 DNS"
            print(f"[proxy] 接收器 {name}：{group.host}:{group.port}"
                  f"（就绪端口 {group.ready_port or '关闭'}，{mode}）", flush=True)

    # ---- DNS 后台解析（每个接收器共享） ----
    async def _resolver_loop(self, group):
        while True:
            try:
                ips, err = await asyncio.wait_for(
                    asyncio.to_thread(resolve_ipv4, group.host, group.port), DNS_TIMEOUT
                )
            except asyncio.TimeoutError:
                ips, err = [], f"DNS 查询超时（{DNS_TIMEOUT}s）"
            changed = group.apply_resolution(ips, err)
            prev_error = self._last_dns_error.get(group.name)
            if err:
                if err != prev_error:
                    self.store.log("event", receiver=group.name,
                                   note=f"接收器 {group.name} 的 DNS 解析失败：{err}"
                                        f"（保留原地址 {group.current_ip or '无'}，自动重试）")
                self._last_dns_error[group.name] = err
            else:
                if prev_error:
                    self.store.log("event", receiver=group.name,
                                   note=f"接收器 {group.name} 的 DNS 已恢复：{group.current_ip}")
                self._last_dns_error[group.name] = None
            if changed:
                old_ip, new_ip = changed
                self.store.log(
                    "event", receiver=group.name,
                    note=f"接收器 {group.name} 的 DNS 地址变更：{old_ip or '无'} → {new_ip}"
                         f"（代次 {group.generation}），活动会话开始改绑")
                self._request_rebinds_for_group(group)
            await asyncio.sleep(DNS_POLL_INTERVAL)

    def _request_rebinds_for_group(self, group):
        with self.lock:
            targets = [
                s for s in self.sessions.values()
                if not s.closed and s.state == "open" and s.receiver_name == group.name
                and s.upstream_ip != group.current_ip
            ]
        for sess in targets:
            self.request_rebind(sess, "DNS 地址变更")

    # ---- 通道准备：建新通道 + 确认同名实例就绪 + DNS 代次校验 ----
    async def _check_ready(self, group, ip):
        """返回 (就绪信息, None) 或 (None, 失败原因)。"""
        checked_at = time.time()
        if not group.ready_port:
            return {"name": group.name, "instance": "", "ready": True,
                    "state": "disabled"}, None
        try:
            body = await asyncio.wait_for(
                asyncio.to_thread(check_ready_sync, ip, group.ready_port, READY_TIMEOUT),
                READY_TIMEOUT + 0.5,
            )
        except Exception as exc:
            msg = f"候选 IP {ip}:{group.ready_port} 就绪查询失败：{type(exc).__name__}: {exc}"
            group.set_ready_info({"ip": ip, "ready": False, "state": "unreachable",
                                  "checked_at": fmt_ts(checked_at), "error": msg})
            return None, msg
        name = body.get("name")
        instance = body.get("instance") or ""
        ready = bool(body.get("ready"))
        info = {
            "ip": ip,
            "name": name,
            "instance": instance,
            "ready": ready,
            "state": body.get("state", "ready" if ready else "not-ready"),
            "checked_at": fmt_ts(checked_at),
            "error": None,
        }
        group.set_ready_info(info)
        if name != group.name:
            return None, (f"候选 IP {ip} 上的接收器名称不匹配："
                          f"期望 {group.name}，实际 {name!r}")
        if not ready:
            return None, (f"候选 IP {ip} 上的同名实例 {instance or '?'} 尚未就绪"
                          f"（state={info['state']}）")
        if not instance:
            return None, f"候选 IP {ip} 的就绪接口未提供实例编号"
        return info, None

    async def _open_channel(self, group, ip):
        """建一条指向 ip:port 的新上游 UDP 通道（独立本地端口）。"""
        last_err = None
        for _ in range(8):
            try:
                port = self.ports.allocate()
            except RuntimeError as exc:
                raise RebindAbort(f"建立新 UDP 通道失败（{ip}:{group.port}）：{exc}")
            try:
                transport, proto = await self.loop.create_datagram_endpoint(
                    lambda: UpstreamProtocol(self),
                    local_addr=("0.0.0.0", port),
                    remote_addr=(ip, group.port),  # connect：只收该接收器的回包
                    family=socket.AF_INET,
                )
                return transport, proto, port
            except OSError as exc:
                last_err = exc
                self.ports.discard(port)
        raise RebindAbort(f"建立新 UDP 通道失败（{ip}:{group.port}）：{last_err}")
    async def _prepare_channel(self, group, ip, gen, hold=None):
        """准备新通道并确认就绪。

        准备与接管必须对应同一个实例：记住确认到的 instance，
        接管前再次查询，实例变化则作废本次准备。
        `hold` 为稳定观察窗口（秒）；建新会话时无需观察窗口。
        """
        if hold is None:
            hold = REBIND_HOLD
        transport = proto = port = None
        try:
            transport, proto, port = await self._open_channel(group, ip)
            info, err = await self._check_ready(group, ip)
            if err:
                raise RebindAbort(err)
            if group.current_ip != ip or group.generation != gen:
                raise RebindAbort(
                    f"DNS 地址在改绑准备期间再次变化（候选 {ip}，代次 {gen} 已过期），"
                    f"本次准备作废")
            if hold:
                # 稳定观察窗口：给 DNS 再次换址留出可观察的时间。
                await asyncio.sleep(hold)
                if group.current_ip != ip or group.generation != gen:
                    raise RebindAbort(
                        f"观察窗口内 DNS 再次换址（候选 {ip}，代次 {gen} 已过期），"
                        f"旧确认不能用于接管")
            info2, err2 = await self._check_ready(group, ip)
            if err2:
                raise RebindAbort("接管前就绪确认失败：" + err2)
            if info2["instance"] != info["instance"]:
                raise RebindAbort(
                    f"接管前实例已变化（准备 {info['instance']}，当前 {info2['instance']}），"
                    f"本次准备作废")
            if group.current_ip != ip or group.generation != gen:
                raise RebindAbort(
                    f"DNS 地址在接管前再次变化（候选 {ip}，代次 {gen} 已过期），本次准备作废")
            return transport, proto, port, info2
        except BaseException:
            if transport is not None:
                proto.retired = True
                transport.close()
            if port is not None:
                self.ports.release(port)
            raise

    # ---- 客户端方向 ----
    def on_client_datagram(self, data, addr):
        now = time.monotonic()
        with self.lock:
            sess = self.sessions.get(addr)
            if sess is not None and sess.closed:
                sess = None
            if (sess is not None and sess.state == "open"
                    and now - sess.last_activity > SESSION_IDLE_TIMEOUT):
                self._close_session(sess, "idle-timeout")
                sess = None
            if sess is None:
                # 建会话：固定到“当前”目标接收器（会话编号从此保持不变）
                sess = Session(self.next_session_id, addr, self.store.get_target())
                self.next_session_id += 1
                self.sessions[addr] = sess
                sess.pending.append(data)
                self.loop.create_task(self._open_session(sess))
                return
            sess.last_activity = now
            if sess.state == "opening":
                if len(sess.pending) < PENDING_MAX:
                    sess.pending.append(data)
                return
        self._forward(sess, data)

    async def _open_session(self, sess):
        group = self.groups.get(sess.receiver_name)
        client = fmt_addr(sess.client_addr)
        attempt = 0
        while True:
            with self.lock:
                if sess.closed:
                    return
            if group is None:
                self._set_open_error(sess, f"未知接收器 {sess.receiver_name}")
                self.close_session(sess, "unknown-receiver")
                return
            ip = group.current_ip
            gen = group.generation
            if ip is None:
                self._set_open_error(
                    sess, "DNS 尚未解析出 IPv4：" + (group.resolve_error or "查询中"))
            else:
                attempt += 1
                try:
                    transport, proto, port, info = await self._prepare_channel(
                        group, ip, gen, hold=0)
                except RebindAbort as exc:
                    self._set_open_error(sess, str(exc))
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # 意外错误也要继续重试建会话
                    self._set_open_error(sess, f"建立通道异常：{type(exc).__name__}: {exc}")
                else:
                    with self.lock:
                        if sess.closed:
                            proto.retired = True
                            transport.close()
                            self.ports.release(port)
                            return
                        if (group.current_ip != ip or group.generation != gen
                                or self.sessions.get(sess.client_addr) is not sess):
                            # 准备期间 DNS 又变了 / 会话已被替换：放弃本次结果。
                            proto.retired = True
                            transport.close()
                            self.ports.release(port)
                            continue
                        sess.upstream_ip = ip
                        sess.upstream_port = port
                        sess.instance = info["instance"]
                        sess.transport = transport
                        sess.proto = proto
                        sess.state = "open"
                        sess.open_error = None
                        proto.session = sess
                        pending, sess.pending = sess.pending, []
                    self.store.log(
                        "event", client=client, session_id=sess.id,
                        receiver=sess.receiver_name, upstream=f"{ip}:{port}",
                        instance=sess.instance,
                        note=f"会话建立，固定到接收器 {sess.receiver_name}"
                             f"（上游 {ip}:{port}，实例 {sess.instance or '未校验'}）")
                    for data in pending:
                        self._forward(sess, data)
                    return
            delay = min(OPEN_RETRY_MIN * (2 ** max(attempt - 1, 0)), OPEN_RETRY_MAX)
            await asyncio.sleep(delay)

    def _set_open_error(self, sess, msg):
        with self.lock:
            if sess.closed:
                return
            prev = sess.open_error
            sess.open_error = msg
        if msg != prev:
            self.store.log("event", client=fmt_addr(sess.client_addr), session_id=sess.id,
                           receiver=sess.receiver_name,
                           note=f"会话建立等待中：{msg}（自动重试）")

    def _forward(self, sess, data):
        with self.lock:
            if sess.closed or sess.transport is None:
                return
            sess.last_activity = time.monotonic()
            upstream = f"{sess.upstream_ip}:{sess.upstream_port}"
            instance = sess.instance
            transport = sess.transport
            receiver = sess.receiver_name
            sid = sess.id
            client = fmt_addr(sess.client_addr)
        try:
            transport.sendto(data)  # 已 connect，原样发往该会话的接收器
        except Exception as exc:
            self.store.log("event", client=client, session_id=sid, receiver=receiver,
                           upstream=upstream, instance=instance,
                           note=f"转发失败: {exc}")
            return
        self.store.log("c2r", client=client, session_id=sid, receiver=receiver,
                       upstream=upstream, instance=instance, payload=preview(data))

    # ---- 接收器方向 ----
    def on_upstream_datagram(self, sess, data):
        now = time.monotonic()
        with self.lock:
            if sess.closed or self.sessions.get(sess.client_addr) is not sess:
                self.store.log("drop", client=fmt_addr(sess.client_addr), session_id=sess.id,
                               receiver=sess.receiver_name,
                               upstream=f"{sess.upstream_ip}:{sess.upstream_port}",
                               instance=sess.instance, payload=preview(data),
                               note="旧会话迟到的回包，已丢弃")
                return
            if now - sess.last_activity > SESSION_IDLE_TIMEOUT:
                self._close_session(sess, "idle-timeout")
                self.store.log("drop", client=fmt_addr(sess.client_addr), session_id=sess.id,
                               receiver=sess.receiver_name,
                               upstream=f"{sess.upstream_ip}:{sess.upstream_port}",
                               instance=sess.instance, payload=preview(data),
                               note="回包到达时会话已过期，已丢弃")
                return
            sess.last_activity = now
            upstream = f"{sess.upstream_ip}:{sess.upstream_port}"
            instance = sess.instance
            receiver = sess.receiver_name
            sid = sess.id
            client_addr = sess.client_addr
            client = fmt_addr(client_addr)
        self.client_transport.sendto(data, client_addr)  # 原样送回该客户端
        self.store.log("r2c", client=client, session_id=sid, receiver=receiver,
                       upstream=upstream, instance=instance, payload=preview(data))

    def on_retired_datagram(self, proto, data, addr):
        """改绑接管后旧通道上迟到的回包：丢弃，绝不转给客户端。"""
        sess = proto.session
        self.store.log(
            "drop",
            client=fmt_addr(sess.client_addr) if sess else "",
            session_id=sess.id if sess else 0,
            receiver=sess.receiver_name if sess else "",
            payload=preview(data),
            note="改绑接管后旧通道的迟到回包，已丢弃（不重发、不转发）")

    # ---- 改绑 ----
    def _retire_channel(self, proto, transport, port):
        """接管后退役旧通道：保持打开收包但一律丢弃，到期再关闭。"""
        if proto is not None:
            proto.retired = True
            proto.retired_at = time.monotonic()
        if transport is None:
            return
        if RETIRED_LINGER <= 0:
            transport.close()
            if port is not None:
                self.ports.release(port)
            return

        def _close():
            transport.close()
            if port is not None:
                self.ports.release(port)

        self.loop.call_later(RETIRED_LINGER, _close)

    def request_rebind(self, sess, reason):
        """为会话启动一次改绑任务（同一会话同时只允许一个）。"""
        with self.lock:
            if sess.closed or sess.state != "open":
                return
            if sess.rebind_task is not None and not sess.rebind_task.done():
                return
            sess.rebind_state = "preparing"
            sess.rebind_reason = reason
            sess.rebind_error = None
            sess.rebind_attempts = 0
            sess.rebind_started_at = time.monotonic()
            sess.last_rebind_at = time.time()
            sess.rebind_task = self.loop.create_task(self._rebind_loop(sess))

    async def _rebind_loop(self, sess):
        try:
            await self._rebind_loop_inner(sess)
        finally:
            with self.lock:
                task = sess.rebind_task
                if task is asyncio.current_task():
                    sess.rebind_task = None

    async def _rebind_loop_inner(self, sess):
        group = self.groups.get(sess.receiver_name)
        if group is None:
            return
        attempt = 0
        while True:
            with self.lock:
                if sess.closed or self.sessions.get(sess.client_addr) is not sess:
                    return  # 迟到的改绑结果：会话已过期/被替换，不再继续
                target_ip = group.current_ip
                gen = group.generation
                if target_ip is not None and target_ip == sess.upstream_ip:
                    sess.rebind_state = "done"
                    sess.rebind_error = None
                    return
            if target_ip is None:
                self._set_rebind_failure(
                    sess, "DNS 解析失败：" + (group.resolve_error or "查询中"), attempt)
            else:
                attempt += 1
                with self.lock:
                    sess.rebind_state = "preparing"
                    sess.rebind_attempts = attempt
                try:
                    transport, proto, port, info = await self._prepare_channel(
                        group, target_ip, gen)
                except RebindAbort as exc:
                    self._set_rebind_failure(sess, str(exc), attempt)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # 任何意外都不能让改绑任务静默退出
                    self._set_rebind_failure(
                        sess, f"改绑准备异常：{type(exc).__name__}: {exc}", attempt)
                else:
                    # 接管：只在会话语义仍有效、DNS 未再换址时生效。
                    with self.lock:
                        if (sess.closed
                                or self.sessions.get(sess.client_addr) is not sess
                                or sess.state != "open"):
                            proto.retired = True
                            transport.close()
                            self.ports.release(port)
                            self.store.log(
                                "event", client=fmt_addr(sess.client_addr),
                                session_id=sess.id, receiver=sess.receiver_name,
                                note="改绑准备结果迟到：会话已过期或被替换，"
                                     "新通道已关闭（不恢复会话）")
                            return
                        if group.current_ip != target_ip or group.generation != gen:
                            proto.retired = True
                            transport.close()
                            self.ports.release(port)
                            self._set_rebind_failure_locked(
                                sess, "接管前 DNS 再次换址，本次改绑作废", attempt)
                        else:
                            old_transport = sess.transport
                            old_proto = sess.proto
                            old_port = sess.upstream_port
                            old_ip = sess.upstream_ip
                            old_instance = sess.instance
                            sess.transport = transport
                            sess.proto = proto
                            sess.upstream_port = port
                            sess.upstream_ip = target_ip
                            sess.instance = info["instance"]
                            sess.state = "open"
                            sess.rebind_state = "done"
                            sess.rebind_error = None
                            sess.last_rebind_at = time.time()
                            proto.session = sess
                            client = fmt_addr(sess.client_addr)
                            sid = sess.id
                            receiver = sess.receiver_name
                            new_upstream = f"{target_ip}:{port}"
                            new_instance = info["instance"]
                    # 退役旧通道：接管后到达的迟到回包一律丢弃（保留观察期便于观察/记录）。
                    if old_transport is not None:
                        self._retire_channel(old_proto, old_transport, old_port)
                    self.store.log(
                        "event", client=client, session_id=sid, receiver=receiver,
                        upstream=new_upstream, instance=new_instance,
                        note=f"改绑完成：{old_ip} → {target_ip}，会话编号 {sid} 不变，"
                             f"实例 {old_instance or '未校验'} → {new_instance}；"
                             f"旧通道已退役，迟到回包丢弃，已发送报文不重发")
                    return
            delay = min(REBIND_RETRY_MIN * (2 ** max(attempt - 1, 0)), REBIND_RETRY_MAX)
            await asyncio.sleep(delay)

    def _set_rebind_failure(self, sess, msg, attempt):
        with self.lock:
            self._set_rebind_failure_locked(sess, msg, attempt)

    def _set_rebind_failure_locked(self, sess, msg, attempt):
        if sess.closed:
            return
        changed = msg != sess.rebind_error
        sess.rebind_state = "retrying"
        sess.rebind_error = msg
        sess.last_rebind_error = msg
        sess.last_rebind_error_at = time.time()
        sess.rebind_attempts = max(attempt, sess.rebind_attempts)
        if changed:
            self.store.log("event", client=fmt_addr(sess.client_addr), session_id=sess.id,
                           receiver=sess.receiver_name,
                           upstream=f"{sess.upstream_ip}:{sess.upstream_port}",
                           instance=sess.instance,
                           note=f"改绑未完成（第 {attempt} 次）：{msg}；保留原通道并自动重试")

    # ---- 会话生命周期 ----
    def _close_session(self, sess, reason):
        """调用方需持有 self.lock。"""
        if sess.closed:
            return
        sess.closed = True
        sess.state = "closed"
        if self.sessions.get(sess.client_addr) is sess:
            del self.sessions[sess.client_addr]
        self._remember_session_locked(sess, reason)
        transport, sess.transport = sess.transport, None
        proto, sess.proto = sess.proto, None
        port, sess.upstream_port = sess.upstream_port, None
        if proto is not None:
            proto.retired = True  # 关闭前已排队的迟到回包也按退役丢弃
        if transport is not None:
            transport.close()  # 迟到的回包到此端口将被系统丢弃
        if port is not None:
            self.ports.release(port)  # 进入冷却期，冷却内不再分配
        task = sess.rebind_task
        cancelled_rebind = task is not None and not task.done()
        if cancelled_rebind:
            task.cancel()  # 任务内部会清理准备中的新通道
            sess.rebind_task = None
        self.store.log("event", client=fmt_addr(sess.client_addr), session_id=sess.id,
                       receiver=sess.receiver_name, note=f"会话关闭（{reason}）")
        if cancelled_rebind:
            self.store.log(
                "event", client=fmt_addr(sess.client_addr), session_id=sess.id,
                receiver=sess.receiver_name,
                note="会话已过期，进行中的改绑已取消：迟到的改绑结果不会恢复过期会话")

    def _remember_session_locked(self, sess, reason=None):
        self.recent_sessions[fmt_addr(sess.client_addr)] = {
            "id": sess.id,
            "client": fmt_addr(sess.client_addr),
            "receiver": sess.receiver_name,
            "upstream_ip": sess.upstream_ip or "",
            "instance": sess.instance,
            "state": "closed",
            "closed_reason": reason,
            "rebind_state": sess.rebind_state,
            "rebind_error": sess.rebind_error or sess.last_rebind_error,
            "rebind_attempts": sess.rebind_attempts,
            "closed_at": time.time(),
        }
        if len(self.recent_sessions) > self.recent_limit:
            oldest = min(self.recent_sessions.items(), key=lambda kv: kv[1].get("closed_at", 0))
            self.recent_sessions.pop(oldest[0], None)

    def close_session(self, sess, reason):
        with self.lock:
            self._close_session(sess, reason)

    async def _sweeper(self):
        while True:
            await asyncio.sleep(0.25)
            now = time.monotonic()
            with self.lock:
                expired = [s for s in self.sessions.values()
                           if not s.closed and now - s.last_activity > SESSION_IDLE_TIMEOUT]
                for sess in expired:
                    self._close_session(sess, "idle-timeout")

    # ---- 快照（供网页） ----
    def _snapshot_session(self, sess, now):
        return {
            "id": sess.id,
            "client": fmt_addr(sess.client_addr),
            "receiver": sess.receiver_name,
            "upstream_ip": sess.upstream_ip or "",
            "upstream": (f"{sess.upstream_ip}:{sess.upstream_port}"
                         if sess.upstream_ip else ""),
            "upstream_port": sess.upstream_port,
            "instance": sess.instance,
            "state": sess.state,
            "idle": round(now - sess.last_activity, 1),
            "age": round(now - sess.created, 1),
            "open_error": sess.open_error,
            "rebind_state": sess.rebind_state,
            "rebind_reason": sess.rebind_reason,
            "rebind_attempts": sess.rebind_attempts,
            "rebind_error": sess.rebind_error,
            "last_rebind_error": sess.last_rebind_error,
            "last_rebind_error_at": fmt_ts_or_none(sess.last_rebind_error_at),
            "last_rebind_at": fmt_ts_or_none(sess.last_rebind_at),
        }

    def snapshot_sessions(self):
        now = time.monotonic()
        with self.lock:
            return [self._snapshot_session(s, now)
                    for s in sorted(self.sessions.values(), key=lambda x: x.id)]

    def snapshot_groups(self):
        with self.lock:
            counts = {}
            for s in self.sessions.values():
                counts[s.receiver_name] = counts.get(s.receiver_name, 0) + 1
        out = []
        for name in sorted(self.groups):
            snap = self.groups[name].snapshot()
            snap["session_count"] = counts.get(name, 0)
            out.append(snap)
        return out

    def session_info_for(self, client):
        """优先返回活动会话；否则返回最近关闭会话的快照（有则）。"""
        now = time.monotonic()
        with self.lock:
            for sess in self.sessions.values():
                if fmt_addr(sess.client_addr) == client and not sess.closed:
                    return self._snapshot_session(sess, now)
            recent = self.recent_sessions.get(client)
            if recent:
                return dict(recent)
        return None


# ---------------- Flask 网页 ----------------
store = Store(DB_PATH)
state = ProxyState(store)
app = Flask(__name__)
app.secret_key = os.urandom(16)

_last_test = {}
_last_test_lock = threading.Lock()

DIRECTION_LABELS = {
    "c2r": "客户端→接收器",
    "r2c": "接收器→客户端",
    "event": "事件",
    "drop": "丢弃",
}


def _format_message(m):
    m = dict(m)
    m["ts"] = fmt_ts(m["ts"])
    m["direction"] = DIRECTION_LABELS.get(m["direction"], m["direction"])
    return m


@app.get("/")
def index():
    with _last_test_lock:
        lt = dict(_last_test) if _last_test else None
    return render_template(
        "index.html",
        target=store.get_target(),
        groups=state.snapshot_groups(),
        receivers={k: f"{d['host']}:{d['port']}" for k, d in RECEIVER_DEFS.items()},
        idle_timeout=SESSION_IDLE_TIMEOUT,
        udp_listen_port=UDP_LISTEN_PORT,
        last_test=lt,
    )


@app.get("/api/state")
def api_state():
    with _last_test_lock:
        lt = dict(_last_test) if _last_test else None
    return jsonify({
        "target": store.get_target(),
        "receivers": {k: f"{d['host']}:{d['port']}" for k, d in RECEIVER_DEFS.items()},
        "groups": state.snapshot_groups(),
        "idle_timeout": SESSION_IDLE_TIMEOUT,
        "sessions": state.snapshot_sessions(),
        "messages": [_format_message(m) for m in store.recent_messages(100)],
        "last_test": lt,
    })


@app.post("/switch")
def switch():
    target = request.form.get("target", "")
    try:
        store.set_target(target)
        store.log("event", note=f"网页切换目标为接收器 {target}")
        flash(f"已切换到接收器 {target}。新会话走 {target}；已建立会话保留编号继续走原接收器，"
              f"原接收器换址时会自动改绑到同名新实例。", "ok")
    except Exception as exc:
        flash(f"切换保存失败，保留原目标 {store.get_target()}。原因：{exc}", "error")
    return redirect(url_for("index"))


@app.post("/test")
def test():
    global _last_test
    result = run_test(
        payload=request.form.get("payload", "PING"),
        delay_s=request.form.get("delay", "").strip(),
        client_port_s=request.form.get("client_port", "").strip(),
        wait_s=request.form.get("wait", "10").strip(),
    )
    with _last_test_lock:
        _last_test = result
    return redirect(url_for("index"))


def run_test(payload, delay_s, client_port_s, wait_s):
    """从网页后端经代理发一条试传报文并等待回包。

    填原客户端端口时复用（或重建）同一客户端的会话；
    结果里带会话编号、实际上游 IP、实例编号与改绑失败原因。
    """
    try:
        wait = min(max(float(wait_s), 0.5), 60.0)
    except ValueError:
        wait = 10.0
    wire = payload
    try:
        delay = float(delay_s)
        if delay > 0:
            wire = f"DELAY:{delay}:{payload}"  # 接收器识别的延迟回包指令
    except ValueError:
        pass
    data = wire.encode()
    result = {"time": fmt_ts(time.time()), "payload": wire, "ok": False,
              "reply": "", "error": "", "rtt": None, "client": "", "client_port": None,
              "receiver": None, "session_id": None, "upstream_ip": "", "upstream": "",
              "instance": "", "rebind_state": "", "rebind_attempts": 0,
              "rebind_error": None, "last_rebind_error": None}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if client_port_s:
            sock.bind(("0.0.0.0", int(client_port_s)))
        sock.settimeout(wait)
        sock.connect(("127.0.0.1", UDP_LISTEN_PORT))
        result["client_port"] = sock.getsockname()[1]
        result["client"] = fmt_addr(sock.getsockname())
        t0 = time.monotonic()
        sock.send(data)
        try:
            reply = sock.recv(65535)
            result["ok"] = True
            result["rtt"] = round(time.monotonic() - t0, 3)
            result["reply"] = preview(reply)
        except socket.timeout:
            result["error"] = f"等待回包超时（{wait}s）"
    except Exception as exc:
        result["error"] = f"发送失败：{exc}"
    finally:
        sock.close()
    # 等代理处理完（含改绑日志），再取会话信息。
    deadline = time.monotonic() + 1.0
    info = None
    while time.monotonic() < deadline:
        if result["client"]:
            info = state.session_info_for(result["client"])
            if info and info.get("state") == "open":
                break
        time.sleep(0.05)
    if info:
        result["session_id"] = info.get("id")
        result["receiver"] = info.get("receiver")
        result["upstream_ip"] = info.get("upstream_ip", "")
        result["upstream"] = info.get("upstream", "")
        if not result["upstream"] and result["upstream_ip"]:
            result["upstream"] = result["upstream_ip"]
        result["instance"] = info.get("instance", "")
        result["rebind_state"] = info.get("rebind_state", "")
        result["rebind_attempts"] = info.get("rebind_attempts", 0)
        result["rebind_error"] = info.get("rebind_error")
        result["last_rebind_error"] = info.get("last_rebind_error")
        result["open_error"] = info.get("open_error")
    if result["receiver"] is None and result["client"]:
        rec = store.latest_client_record(result["client"])
        if rec:
            result["session_id"] = rec["session_id"]
            result["receiver"] = rec["receiver"]
            result["upstream"] = rec["upstream"]
            result["upstream_ip"] = rec["upstream"].split(":")[0] if rec["upstream"] else ""
            result["instance"] = rec["instance"]
    return result


# ---------------- 启动：asyncio 线程 + Flask 主线程 ----------------
def _run_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    state.loop = loop
    loop.run_until_complete(state.start())
    loop.run_forever()


def main():
    t = threading.Thread(target=_run_loop, name="udp-proxy-loop", daemon=True)
    t.start()
    print(f"[proxy] 操作网页 http://{HTTP_HOST}:{HTTP_PORT}", flush=True)
    app.run(host=HTTP_HOST, port=HTTP_PORT, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
