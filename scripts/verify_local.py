#!/usr/bin/env python3
"""本地端到端验证：不依赖 Docker，直接以子进程启动接收器和代理，逐项验证需求。

用法：python3 scripts/verify_local.py

“服务名不变、IPv4 变化”用回环地址 + 一个本地 hosts 覆盖文件模拟：
receiver-a 先解析到 127.0.0.2，重建后解析到 127.0.0.3 / 127.0.0.5 / 127.0.0.7 …
（127.0.0.9 表示不可达候选 IP，127.0.0.8 上放一个名称不对的实例）。
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXY_PY = os.path.join(ROOT, "proxy", "app.py")
RECEIVER_PY = os.path.join(ROOT, "receiver", "receiver.py")

UDP_PORT = 19000
HTTP_PORT = 18080
BASE = f"http://127.0.0.1:{HTTP_PORT}"

RX_PORT = 19001
READY_A = 20002
READY_B = 20022

IP_A1 = "127.0.0.2"   # A 的原 IPv4
IP_A2 = "127.0.0.3"   # A 重建后的 IPv4
IP_A3 = "127.0.0.5"   # 再次换址，延迟就绪
IP_A4 = "127.0.0.6"   # 改绑准备期间被替换掉的候选
IP_A5 = "127.0.0.7"   # 最终地址
IP_WRONG = "127.0.0.8"  # 放了名称不匹配实例的地址
IP_DEAD = "127.0.0.9"   # 不可达候选
IP_B = "127.0.0.4"

NAME_A = "receiver-a"
NAME_B = "receiver-b"

_failures = []


def check(name, cond, detail=""):
    mark = "PASS" if cond else "FAIL"
    print(f"[{mark}] {name}" + (f"  -- {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


# ---------------- HTTP 工具 ----------------
def http_get(path, timeout=10):
    with urllib.request.urlopen(BASE + path, timeout=timeout) as r:
        return json.load(r)


def http_post(path, data):
    with urllib.request.urlopen(
        BASE + path, data=urllib.parse.urlencode(data).encode(), timeout=60
    ) as r:
        return r.status


def wait_http_up(timeout=20):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            http_get("/api/state")
            return True
        except Exception:
            time.sleep(0.2)
    return False


def wait_until(predicate, timeout, interval=0.1):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            val = predicate()
        except Exception:
            val = None
        if val:
            return val
        time.sleep(interval)
    return None


def state():
    return http_get("/api/state")


def group(name):
    return {x["name"]: x for x in state()["groups"]}[name]


def sessions_by_client(client):
    return [s for s in state()["sessions"] if s["client"] == client]


def session_of(client):
    ss = sessions_by_client(client)
    return ss[0] if ss else None


def messages_for(client, direction=None, text=None):
    out = []
    for m in state()["messages"]:
        if m["client"] != client:
            continue
        if direction and m["direction"] != direction:
            continue
        if text and text not in m["payload"] and text not in m["note"]:
            continue
        out.append(m)
    return out


def event_notes(text):
    return [m["note"] for m in state()["messages"]
            if m["direction"] == "事件" and text in m["note"]]


# ---------------- UDP 工具 ----------------
def udp_client():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("127.0.0.1", UDP_PORT))
    return s


def send_recv(sock, payload: bytes, timeout=5.0):
    sock.settimeout(timeout)
    sock.send(payload)
    return sock.recv(65535)


def drain(sock, seconds):
    got = []
    sock.settimeout(0.1)
    end = time.time() + seconds
    while time.time() < end:
        try:
            got.append(sock.recv(65535))
        except socket.timeout:
            pass
    return got


# ---------------- hosts 覆盖文件（模拟 DNS 更新） ----------------
def write_hosts(path, mapping):
    lines = []
    for name, ips in mapping.items():
        if not ips:
            continue
        if isinstance(ips, str):
            ips = [ips]
        lines.append(f"{' '.join(ips)} {name}")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    os.replace(tmp, path)


class Receiver:
    """一个接收器进程；name 是逻辑名（A/B），DNS 服务名由 hosts 文件决定。"""

    def __init__(self, name, ip, ready_port, logdir, tag, ready_delay=0.0):
        self.name = name
        self.ip = ip
        self.ready_port = ready_port
        log = open(os.path.join(logdir, f"receiver-{tag}.log"), "w")
        env = dict(
            os.environ,
            RECEIVER_NAME=name,
            LISTEN_PORT=str(RX_PORT),
            BIND_HOST=ip,
            HTTP_HOST=ip,
            HTTP_PORT=str(ready_port),
            REPLY_DELAY="0",
            READY_DELAY=str(ready_delay),
        )
        self.proc = subprocess.Popen([sys.executable, RECEIVER_PY], env=env,
                                     stdout=log, stderr=subprocess.STDOUT)
        self.log = log

    def ready_info(self):
        with urllib.request.urlopen(
            f"http://{self.ip}:{self.ready_port}/readyz", timeout=2
        ) as r:
            return json.load(r)

    def stop(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
                self.proc.wait(timeout=2)
            except Exception:
                pass
        try:
            self.log.close()
        except Exception:
            pass


class Proxy:
    def __init__(self, db_path, logdir, tag, hosts_path, idle_timeout=20,
                 rebind_hold=1.2, env_extra=None):
        env = dict(
            os.environ,
            UDP_LISTEN_PORT=str(UDP_PORT), HTTP_PORT=str(HTTP_PORT),
            RECEIVER_A_HOST=NAME_A, RECEIVER_A_PORT=str(RX_PORT),
            RECEIVER_A_READY_PORT=str(READY_A),
            RECEIVER_B_HOST=NAME_B, RECEIVER_B_PORT=str(RX_PORT),
            RECEIVER_B_READY_PORT=str(READY_B),
            SESSION_IDLE_TIMEOUT=str(idle_timeout),
            DB_PATH=db_path,
            RESOLVER_HOSTS_FILE=hosts_path,
            DNS_POLL_INTERVAL="0.2",
            DNS_TIMEOUT="2",
            REBIND_HOLD=str(rebind_hold),
            REBIND_RETRY_MIN="0.2",
            REBIND_RETRY_MAX="0.5",
            OPEN_RETRY_MIN="0.2",
            OPEN_RETRY_MAX="0.5",
            READY_TIMEOUT="0.6",
            RETIRED_LINGER="8",
            LOG_KEEP="3000",
        )
        if env_extra:
            env.update(env_extra)
        self.proc = subprocess.Popen(
            [sys.executable, PROXY_PY], env=env,
            stdout=open(os.path.join(logdir, f"proxy-{tag}.log"), "w"),
            stderr=subprocess.STDOUT)

    def stop(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        except Exception:
            try:
                self.proc.kill()
                self.proc.wait(timeout=2)
            except Exception:
                pass


def main():
    tmp = tempfile.mkdtemp(prefix="proxy-verify-")
    db_path = os.path.join(tmp, "proxy.db")
    hosts_path = os.path.join(tmp, "hosts")
    mapping = {NAME_A: IP_A1, NAME_B: IP_B}
    write_hosts(hosts_path, mapping)

    procs = []
    receivers = {}
    proxy = None

    def start_receiver(name, ip, ready_port, tag, ready_delay=0.0):
        r = Receiver(name, ip, ready_port, tmp, tag, ready_delay)
        receivers[tag] = r
        procs.append(r.proc)
        return r

    def set_hosts(**changes):
        mapping.update(changes)
        write_hosts(hosts_path, mapping)

    def start_proxy(tag, idle_timeout=20, rebind_hold=1.2):
        nonlocal proxy
        proxy = Proxy(db_path, tmp, tag, hosts_path, idle_timeout, rebind_hold)
        procs.append(proxy.proc)
        return wait_http_up()

    a_old = start_receiver("A", IP_A1, READY_A, "a-old")
    b_main = start_receiver("B", IP_B, READY_B, "b")
    start_proxy("run1")

    try:
        check("接收器 A 旧实例就绪接口可用",
              wait_until(lambda: a_old.ready_info().get("ready"), 5) is not None)
        check("后台 DNS 初始解析完成",
              wait_until(lambda: group("A")["current_ip"] == IP_A1
                         and group("B")["current_ip"] == IP_B, 15) is not None)
        print(f"--- 环境就绪（日志目录 {tmp}）---")

        # ============ 1. 基础行为 ============
        check("初始目标为 A", state()["target"] == "A")
        c1 = udp_client()
        client1 = f"127.0.0.1:{c1.getsockname()[1]}"
        m1 = b"m1-hello"
        check("报文原样回传", send_recv(c1, m1) == m1)
        time.sleep(0.2)
        e = messages_for(client1, "客户端→接收器", "m1-hello")
        check("m1 实际上游为 A 的旧 IPv4",
              bool(e) and e[0]["upstream"].startswith(IP_A1 + ":"), str(e))
        s1 = session_of(client1)
        check("会话已建立且有编号", bool(s1) and s1["id"] >= 1, str(s1))
        sid1 = s1["id"]
        inst_a1 = s1["instance"]
        check("会话记录了已确认实例编号", bool(inst_a1), str(s1))
        check("实例编号与接收器就绪接口一致",
              inst_a1 == a_old.ready_info()["instance"], f"{inst_a1}")

        blob = bytes(range(256))
        check("二进制报文原样透传", send_recv(c1, blob) == blob)

        # 网页切到 B：旧会话不去 B
        http_post("/switch", {"target": "B"})
        check("网页切换后当前目标为 B", state()["target"] == "B")
        m2 = b"m2-stick"
        check("旧会话报文仍有回包", send_recv(c1, m2) == m2)
        time.sleep(0.2)
        e = messages_for(client1, "客户端→接收器", "m2-stick")
        check("网页切到 B 后旧会话仍走 A",
              bool(e) and e[0]["upstream"].startswith(IP_A1 + ":"), str(e))

        # ============ 2. 接管后旧通道迟到回包丢弃、已发送报文不重发 ============
        print("--- 旧通道迟到回包（发送后立即触发同名换址）---")
        a_new = start_receiver("A", IP_A2, READY_A, "a-new")
        check("重建实例 A 就绪",
              wait_until(lambda: a_new.ready_info().get("ready"), 5) is not None)
        http_post("/switch", {"target": "A"})  # 迟到用例建立在 A 的旧地址上
        check("目标切回 A", state()["target"] == "A")
        c_late = udp_client()
        client_late = f"127.0.0.1:{c_late.getsockname()[1]}"
        # 报文 5 秒后由旧实例回包；期间 DNS 换址并完成接管
        c_late.send(b"DELAY:5:late1")  # 旧实例 5 秒后才回包
        check("迟到用例会话建立在 A 的旧 IPv4 上",
              wait_until(lambda: bool(messages_for(client_late, "客户端→接收器", "late1")), 5)
              and (messages_for(client_late, "客户端→接收器", "late1") or [{}])[0]
              .get("upstream", "").startswith(IP_A1 + ":"),
              str(messages_for(client_late, "客户端→接收器", "late1")))
        set_hosts(**{NAME_A: IP_A2})
        ok = wait_until(lambda: (session_of(client_late) or {}).get("upstream_ip") == IP_A2
                        and session_of(client_late)["rebind_state"] == "done", 10)
        check("DNS 换址后活动会话自动改绑到新 IPv4", bool(ok),
              str(session_of(client_late)))
        check("改绑后确认的是新实例",
              (session_of(client_late) or {}).get("instance") == a_new.ready_info()["instance"])
        got_late = drain(c_late, 6.0)  # 旧实例的 5 秒回包应被丢弃
        check("接管后旧通道迟到的回包未送达客户端",
              not any(b"late1" in g for g in got_late), str(got_late))
        drop_entries = messages_for(client_late, "丢弃", "late1")
        check("日志记录旧通道迟到回包已丢弃",
              any("旧通道" in m["note"] for m in drop_entries), str(drop_entries))
        check("已发送的报文不重发",
              len(messages_for(client_late, "客户端→接收器", "late1")) == 1)
        http_post("/switch", {"target": "B"})
        check("目标恢复为 B", state()["target"] == "B")

        # ============ 3. 网页已切到 B：A 的旧会话保留编号并在 A 新地址恢复 ============
        ok = wait_until(lambda: (session_of(client1) or {}).get("upstream_ip") == IP_A2
                        and session_of(client1)["rebind_state"] == "done", 10)
        check("网页目标为 B 时 A 的旧会话仍在 A 的新地址恢复", bool(ok),
              str(session_of(client1)))
        check("旧会话编号保持不变", (session_of(client1) or {}).get("id") == sid1)
        m3 = b"m3-a-new-ip"
        check("原客户端端口在 A 的新地址收发正常", send_recv(c1, m3) == m3)
        time.sleep(0.2)
        e = messages_for(client1, "客户端→接收器", "m3-a-new-ip")
        check("m3 实际上游为 A 的新 IPv4",
              bool(e) and e[0]["upstream"].startswith(IP_A2 + ":"), str(e))

        # ============ 4. 新实例延迟就绪：等待期间原通道照常收发 ============
        print("--- A 再次换址，新实例延迟 4 秒就绪 ---")
        a_slow = start_receiver("A", IP_A3, READY_A, "a-slow", ready_delay=4.0)
        set_hosts(**{NAME_A: IP_A3})
        time.sleep(0.5)
        m4 = b"m4-while-warming"
        check("等待确认就绪期间原通道照常收发", send_recv(c1, m4) == m4)
        time.sleep(0.2)
        s_now = session_of(client1)
        check("未就绪时不交接（上游仍为旧 IPv4）",
              bool(s_now) and s_now["upstream_ip"] == IP_A2, str(s_now))
        check("未就绪时网页显示改绑失败原因",
              bool(s_now) and "尚未就绪" in (s_now["rebind_error"] or ""), str(s_now))
        check("未就绪时原通道上的报文照常发出",
              any(mm["upstream"].startswith(IP_A2 + ":")
                  for mm in messages_for(client1, "客户端→接收器", "m4-while-warming")))
        check("未就绪时会话编号不变", bool(s_now) and s_now["id"] == sid1)
        ok = wait_until(lambda: (session_of(client1) or {}).get("upstream_ip") == IP_A3
                        and session_of(client1)["rebind_state"] == "done", 15)
        check("延迟就绪后自动改绑到新实例", bool(ok), str(session_of(client1)))
        check("延迟就绪后会话编号不变", (session_of(client1) or {}).get("id") == sid1)
        check("延迟就绪后确认的是该实例",
              (session_of(client1) or {}).get("instance") == a_slow.ready_info()["instance"])
        m5 = b"m5-after-warm"
        check("延迟就绪后在新地址收发正常", send_recv(c1, m5) == m5)

        # ============ 5. DNS 在确认/接管期间再次换址：旧确认不能接管 ============
        print("--- DNS 再次换址：旧确认不能接管 ---")
        a_flap = start_receiver("A", IP_A4, READY_A, "a-flap")
        a_final = start_receiver("A", IP_A5, READY_A, "a-final")
        check("两个候选实例均就绪",
              wait_until(lambda: a_flap.ready_info().get("ready")
                         and a_final.ready_info().get("ready"), 5) is not None)
        set_hosts(**{NAME_A: IP_A4})          # 第一候选
        time.sleep(0.5)                        # 代理进入准备/观察窗口
        set_hosts(**{NAME_A: IP_A5})          # 观察窗口内再次换址
        ok = wait_until(lambda: (session_of(client1) or {}).get("upstream_ip") == IP_A5
                        and session_of(client1)["rebind_state"] == "done", 15)
        check("最终改绑到最新 IPv4", bool(ok), str(session_of(client1)))
        check("旧确认未被用于接管（没有改绑完成到被替换的候选地址）",
              not event_notes(f"改绑完成：{IP_A3} → {IP_A4}"),
              str(event_notes("改绑完成")))
        check("记录旧确认作废原因",
              bool(event_notes("作废") or event_notes("旧确认")),
              str(event_notes("改绑")))
        check("换址取消期间会话编号不变", (session_of(client1) or {}).get("id") == sid1)
        m6 = b"m6-latest-ip"
        check("最新地址上收发正常", send_recv(c1, m6) == m6)

        # ============ 6. 解析失败：保留原通道并自动重试 ============
        print("--- DNS 解析失败 ---")
        prev_ip = IP_A5
        del mapping[NAME_A]
        write_hosts(hosts_path, mapping)
        time.sleep(0.5)
        g = group("A")
        check("网页显示 DNS 解析失败原因", bool(g["resolve_error"]), str(g))
        check("解析失败时保留上一次成功 IPv4", g["current_ip"] == prev_ip, str(g))
        check("解析失败期间原通道照常收发", send_recv(c1, b"m7-dnsfail") == b"m7-dnsfail")
        s_now = session_of(client1)
        check("解析失败期间会话仍保留原通道",
              bool(s_now) and s_now["upstream_ip"] == prev_ip, str(s_now))
        set_hosts(**{NAME_A: IP_A5})
        check("DNS 恢复后自动重试成功",
              wait_until(lambda: not group("A")["resolve_error"], 10) is not None)

        # ============ 7. 就绪确认失败（候选不可达）：保留原通道并重试 ============
        print("--- 候选 IPv4 不可达 ---")
        set_hosts(**{NAME_A: IP_DEAD})
        ok = wait_until(lambda: "就绪" in ((session_of(client1) or {}).get("rebind_error") or ""), 10)
        s_now = session_of(client1)
        check("不可达候选导致改绑失败并自动重试",
              bool(ok) and s_now["rebind_state"] in ("retrying", "preparing"), str(s_now))
        check("确认失败时保留原通道", bool(s_now) and s_now["upstream_ip"] == prev_ip, str(s_now))
        check("确认失败期间原通道照常收发",
              send_recv(c1, b"m8-dead-candidate") == b"m8-dead-candidate")
        set_hosts(**{NAME_A: IP_A5})
        check("候选恢复后改绑收敛",
              wait_until(lambda: (session_of(client1) or {}).get("rebind_error") is None
                         and (session_of(client1) or {}).get("upstream_ip") == IP_A5, 15) is not None)

        # ============ 8. 同名位置上的错误名称实例不接管 ============
        print("--- 候选实例名称不匹配 ---")
        wrong = start_receiver("B", IP_WRONG, READY_A, "wrong-name")
        check("错误名称实例就绪",
              wait_until(lambda: wrong.ready_info().get("ready"), 5) is not None)
        set_hosts(**{NAME_A: IP_WRONG})
        check("名称不匹配时拒绝接管",
              wait_until(lambda: "名称不匹配" in ((session_of(client1) or {}).get("rebind_error") or ""), 10)
              is not None, str(session_of(client1)))
        s_now = session_of(client1)
        check("名称不匹配时保留原通道", bool(s_now) and s_now["upstream_ip"] == IP_A5, str(s_now))
        check("名称不匹配时原通道照常收发",
              send_recv(c1, b"m9-wrong-name") == b"m9-wrong-name")
        set_hosts(**{NAME_A: IP_A5})
        check("恢复正确名称后改绑收敛",
              wait_until(lambda: (session_of(client1) or {}).get("rebind_error") is None, 10) is not None)

        # ============ 9. 网页试传：原客户端端口、会话编号、实际 IP、回包、失败原因 ============
        print("--- 网页试传（原客户端端口）---")
        port_c1 = c1.getsockname()[1]
        c1.close()  # 交给网页试传用同一客户端端口重发（复用原会话）
        time.sleep(0.2)
        http_post("/test", {"payload": "webtest1", "wait": "5", "delay": "0",
                            "client_port": str(port_c1)})
        lt = state()["last_test"]
        check("网页试传成功且回包一致", bool(lt) and lt["ok"] and lt["reply"] == "webtest1",
              str(lt))
        check("网页试传显示会话编号", bool(lt) and lt.get("session_id") == sid1, str(lt))
        check("网页试传显示实际上游 IP", bool(lt) and lt.get("upstream_ip") == IP_A5, str(lt))
        check("网页试传显示已确认实例",
              bool(lt) and lt.get("instance") == a_final.ready_info()["instance"], str(lt))
        check("网页试传显示回包 RTT", bool(lt) and lt.get("rtt") is not None, str(lt))
        # 制造改绑失败，再次用原端口试传：显示失败原因，回包仍来自原通道
        set_hosts(**{NAME_A: IP_DEAD})
        wait_until(lambda: (session_of(client1) or {}).get("rebind_error") is not None, 10)
        http_post("/test", {"payload": "webtest2", "wait": "5", "delay": "0",
                            "client_port": str(port_c1)})
        lt = state()["last_test"]
        check("改绑失败时网页试传仍成功（原通道）", bool(lt) and lt["ok"], str(lt))
        check("网页显示改绑失败原因",
              bool(lt) and bool(lt.get("last_rebind_error") or lt.get("rebind_error")), str(lt))
        check("改绑失败时网页试传仍显示原会话编号",
              bool(lt) and lt.get("session_id") == sid1, str(lt))
        set_hosts(**{NAME_A: IP_A5})
        wait_until(lambda: (session_of(client1) or {}).get("rebind_error") is None, 10)

        # ============ 10. 迟到的改绑结果不能恢复过期会话 ============
        print("--- 会话过期后，迟到的改绑结果不得恢复 ---")
        proxy.stop()
        check("短空闲超时代理启动", start_proxy("run2", idle_timeout=2, rebind_hold=0.2))
        http_post("/switch", {"target": "A"})
        check("目标切回 A", state()["target"] == "A")
        a_late = start_receiver("A", "127.0.0.10", READY_A, "a-late", ready_delay=8.0)
        # 先建立在可用的 A 上（IP_A5），再换址到延迟就绪的新实例，让改绑任务挂起
        set_hosts(**{NAME_A: IP_A5})
        wait_until(lambda: group("A")["current_ip"] == IP_A5, 10)
        c_exp = udp_client()
        client_exp = f"127.0.0.1:{c_exp.getsockname()[1]}"
        check("过期用例会话在可用实例上建立",
              send_recv(c_exp, b"before-expiry", timeout=6) == b"before-expiry")
        drain(c_exp, 0.3)
        set_hosts(**{NAME_A: "127.0.0.10"})
        ok = wait_until(lambda: "尚未就绪" in ((session_of(client_exp) or {}).get("rebind_error") or ""), 10)
        sid_exp = (session_of(client_exp) or {}).get("id")
        check("过期用例会话进入等待改绑/就绪", bool(ok) and bool(sid_exp),
              str(session_of(client_exp)))
        check("等待期间原通道仍可用",
              (session_of(client_exp) or {}).get("upstream_ip") == IP_A5,
              str(session_of(client_exp)))
        # 空闲 2 秒后会话过期；候选实例 6 秒后才就绪，其改绑结果迟到
        gone = wait_until(lambda: session_of(client_exp) is None, 10)
        check("空闲超时后会话过期", bool(gone))
        got = drain(c_exp, 1.5)
        check("过期后未收到任何回包", got == [], str(got))
        check("数值化时间后候选实例最终就绪",
              wait_until(lambda: a_late.ready_info().get("ready"), 10) is not None)
        check("迟到的改绑结果未恢复过期会话", session_of(client_exp) is None)
        check("日志说明进行中的改绑已取消、不会恢复过期会话",
              any("不会恢复过期会话" in n for n in event_notes("改绑")),
              str(event_notes("改绑")))
        c_exp.send(b"new-session-after-expiry")
        time.sleep(0.6)
        new_sess = session_of(client_exp)
        check("同客户端端口重建为全新会话（新编号）",
              bool(new_sess) and new_sess["id"] != sid_exp, str(new_sess))
        http_post("/switch", {"target": "B"})

        # ============ 11. 过期会话的迟到回包不投递 ============
        print("--- 过期后迟到回包不投递 ---")
        set_hosts(**{NAME_A: IP_A5})
        wait_until(lambda: group("A")["current_ip"] == IP_A5, 10)
        c2 = udp_client()
        client2 = f"127.0.0.1:{c2.getsockname()[1]}"
        c2.send(b"DELAY:5:late-expired")
        time.sleep(2.6)  # 空闲 2 秒即过期
        check("过期后新会话报文有回包", send_recv(c2, b"ping2", timeout=4) == b"ping2")
        got = drain(c2, 4.0)
        check("过期会话的迟到回包未送达", not any(b"late-expired" in g for g in got), str(got))
        check("迟到回包未出现在下发日志中",
              not messages_for(client2, "接收器→客户端", "late-expired"),
              str(messages_for(client2, "接收器→客户端", "late-expired")))

        # ============ 12. 重启：目标保留、会话清空 ============
        print("--- 重启 ---")
        proxy.stop()
        check("代理重启后恢复", start_proxy("run3", idle_timeout=5))
        st = state()
        check("重启后目标保留", st["target"] == "B")
        check("重启后会话已清空", st["sessions"] == [])
        c3 = udp_client()
        c3.settimeout(5)
        c3.send(b"after-restart")
        check("重启后仍可收发", c3.recv(65535) == b"after-restart")
        time.sleep(0.3)
        client3 = f"127.0.0.1:{c3.getsockname()[1]}"
        e = messages_for(client3, "客户端→接收器", "after-restart")
        check("重启后新会话走目标接收器 B",
              bool(e) and e[0]["receiver"] == "B", str(e))

        # ============ 13. 切换保存失败保留原目标 ============
        sys.path.insert(0, os.path.join(ROOT, "proxy"))
        os.environ["DB_PATH"] = os.path.join(tmp, "other.db")
        import importlib
        import app as proxy_app
        importlib.reload(proxy_app)
        s = proxy_app.Store(os.path.join(tmp, "t.db"))
        s.set_target("B")
        s._conn.close()
        failed = False
        try:
            s.set_target("A")
        except Exception:
            failed = True
        check("保存失败时切换报错且保留原目标", failed and s.get_target() == "B")

    finally:
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in procs:
            try:
                p.wait(timeout=5)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    print("---")
    if _failures:
        print(f"共 {len(_failures)} 项失败:")
        for name in _failures:
            print(f"  - {name}")
        return 1
    print("全部验证通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
