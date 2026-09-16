#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IronWall v1.28.8 - Decoy Port Trap Manager
七层假端口陷阱：每层随机生成多个高段端口，攻击者一旦连接，
连接会被长期吞没，来源 IP 自动写入审计日志并联动 fail2ban 全端口封禁。

用法（root）：python3 decoy-port-manager.py
推荐由 install-decoy-ports.sh 安装为 systemd 服务。
启动与轮换时会全量对账防火墙，自动清除历史遗留的假端口。
"""

import json
import os
import re
import random
import select
import socket
import subprocess
import sys
import threading
import time

STATE_FILE = "/www/wwwroot/jdy-cloud/logs/decoy-port-state.json"
HIT_LOG = "/www/wwwroot/jdy-cloud/logs/decoy-port-hits.log"
STATIC_WHITELIST = {"203.0.113.10", "203.0.113.11"}
DYNAMIC_WHITELIST_FILE = "/www/wwwroot/jdy-cloud/logs/portscan-dynamic-whitelist.json"
# 常见服务端口：诱饵端口永不占用。
# 你实际占用的其他端口（管理面板、改过的 SSH 等）用环境变量
# IRONWALL_RESERVED_PORTS 追加（逗号分隔），避免诱饵与真实业务撞车。
BASE_RESERVED = {21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                 3306, 33060, 8080, 8083, 888, 1723, 5000, 8000}


def _reserved_ports():
    ports = set(BASE_RESERVED)
    for token in os.environ.get("IRONWALL_RESERVED_PORTS", "").split(","):
        token = token.strip()
        if not token:
            continue
        try:
            port = int(token)
        except ValueError:
            continue
        if 0 < port <= 65535:
            ports.add(port)
    return ports


RESERVED = _reserved_ports()
PORT_MIN = 31000
PORT_MAX = 64999
LAYERS = 7
PORTS_PER_LAYER = 3
ROTATE_SECONDS = 6 * 3600
HOLD_SECONDS = 180
# IronWall v1.47.7: 并发吞没线程硬上限——攻击者刷假端口时防御工具自身不被打穿
MAX_HOLD_THREADS = 256
HOLD_SLOTS = threading.BoundedSemaphore(MAX_HOLD_THREADS)


def load_dynamic_whitelist():
    entries = {}
    try:
        if os.path.isfile(DYNAMIC_WHITELIST_FILE):
            with open(DYNAMIC_WHITELIST_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            now = time.time()
            for candidate, expiry in data.items():
                try:
                    if int(expiry) > now:
                        entries[candidate] = int(expiry)
                except Exception:
                    continue
    except Exception:
        pass
    return entries


def is_whitelisted(ip):
    if ip in STATIC_WHITELIST:
        return True
    return ip in load_dynamic_whitelist()


def log_hit(ip, port, layer):
    line = "%s ip=%s port=%s layer=%s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), ip, port, layer)
    try:
        with open(HIT_LOG, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass
    if is_whitelisted(ip):
        return
    try:
        subprocess.run(["fail2ban-client", "set", "ironwall", "banip", ip],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def open_port_firewall(port):
    try:
        subprocess.run(["firewall-cmd", "--permanent", "--add-port=%s/tcp" % port],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def close_port_firewall(port):
    try:
        subprocess.run(["firewall-cmd", "--permanent", "--remove-port=%s/tcp" % port],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def reload_firewall():
    try:
        subprocess.run(["firewall-cmd", "--reload"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def sync_firewall_ports(wanted, old_ports=None):
    wanted = set(int(p) for p in wanted)
    stale = set()
    if old_ports:
        for p in old_ports:
            try:
                p = int(p)
                if PORT_MIN <= p <= PORT_MAX and p not in RESERVED:
                    stale.add(p)
            except Exception:
                pass
    try:
        raw = subprocess.run(["firewall-cmd", "--permanent", "--list-ports"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             universal_newlines=True, timeout=10).stdout
        for m in re.findall(r"(\d+)/tcp", raw):
            port = int(m)
            if PORT_MIN <= port <= PORT_MAX and port not in RESERVED:
                stale.add(port)
    except Exception:
        pass
    stale -= wanted
    removed = []
    for port in sorted(stale):
        close_port_firewall(port)
        removed.append(port)
    for port in sorted(wanted):
        open_port_firewall(port)
    if removed:
        print("firewall sync: removed %d stale port(s): %s" % (len(removed), removed))
    reload_firewall()


def generate_layers():
    used = set(RESERVED)
    layers = []
    for layer in range(1, LAYERS + 1):
        ports = []
        attempts = 0
        while len(ports) < PORTS_PER_LAYER and attempts < 10000:
            attempts += 1
            port = random.randint(PORT_MIN, PORT_MAX)
            if port not in used:
                used.add(port)
                ports.append(port)
        layers.append({"layer": layer, "service": service_name(layer), "ports": ports})
    return layers


def service_name(layer):
    names = {1: "ops-http", 2: "redis-cache", 3: "mongo-admin", 4: "backup-rsync",
             5: "monitor-agent", 6: "object-storage", 7: "gitlab-runner"}
    return names.get(layer, "decoy-service")


def bind_port(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.listen(64)
        sock.setblocking(False)
        return sock
    except Exception:
        return None


def hold_connection(conn, addr, port, layer):
    ip = addr[0] if addr else "unknown"
    log_hit(ip, port, layer)
    until = time.time() + HOLD_SECONDS
    try:
        conn.settimeout(1.0)
        while time.time() < until:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                # 黑洞：不返回任何业务数据
            except socket.timeout:
                continue
            except Exception:
                break
    finally:
        try:
            conn.close()
        except Exception:
            pass
        try:
            HOLD_SLOTS.release()
        except ValueError:
            pass


def write_state(layers, total_hits, previous_ports=None):
    data = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "layers": layers,
        "total_hits": total_hits,
    }
    if previous_ports is not None:
        data["previous_ports"] = previous_ports
    try:
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        os.rename(tmp, STATE_FILE)
        os.chmod(STATE_FILE, 0o644)
    except Exception as e:
        print("write state failed: %s" % e, file=sys.stderr)


def load_hits():
    try:
        if os.path.isfile(STATE_FILE):
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return int(data.get("total_hits", 0) or 0)
    except Exception:
        pass
    return 0


def main():
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    total_hits = load_hits()
    listeners = {}
    current_ports = []

    def start_listeners(layers, old_ports=None):
        nonlocal listeners, current_ports
        for sock in listeners.values():
            try:
                sock.close()
            except Exception:
                pass
        listeners = {}
        current_ports = []
        for layer_info in layers:
            for port in layer_info["ports"]:
                sock = bind_port(port)
                if sock is not None:
                    listeners[port] = (sock, layer_info["layer"])
                    current_ports.append(port)
        sync_firewall_ports(current_ports, old_ports)
        write_state(layers, total_hits, current_ports)
        print("listeners: %s" % current_ports)

    layers = generate_layers()
    old_ports = []
    if os.path.isfile(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                old = json.load(f)
            old_ports = old.get("previous_ports", [])
        except Exception:
            old_ports = []
    start_listeners(layers, old_ports)

    last_rotate = time.time()
    try:
        while True:
            socks = [sock for sock, _ in listeners.values()]
            if not socks:
                time.sleep(5)
                layers = generate_layers()
                start_listeners(layers, current_ports)
                last_rotate = time.time()
                continue
            readable, _, _ = select.select(socks, [], [], 1.0)
            for sock in readable:
                try:
                    conn, addr = sock.accept()
                    port = sock.getsockname()[1]
                    layer = listeners.get(port, (None, 0))[1]
                    ip = addr[0] if addr else "unknown"
                    total_hits += 1
                    write_state(layers, total_hits, current_ports)
                    if not HOLD_SLOTS.acquire(blocking=False):
                        # 超限：仍记录命中并联动 fail2ban，但立即断开，不再吞没资源
                        log_hit(ip, port, layer)
                        try:
                            conn.close()
                        except Exception:
                            pass
                        continue
                    t = threading.Thread(target=hold_connection, args=(conn, addr, port, layer), daemon=True)
                    t.start()
                except Exception:
                    pass
            if time.time() - last_rotate >= ROTATE_SECONDS:
                layers = generate_layers()
                start_listeners(layers, current_ports)
                last_rotate = time.time()
    except KeyboardInterrupt:
        pass
    finally:
        for sock, _ in listeners.values():
            try:
                sock.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
