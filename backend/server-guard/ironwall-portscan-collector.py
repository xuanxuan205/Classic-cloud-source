#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IronWall v1.26.1 - 陷阱触碰联动采集器（替代“自动扫描端口统计”）

设计变更：
- 不再读取 firewalld REJECT/DROP 日志做“N 端口探测”统计，避免正常流量误封。
- 只读取假端口陷阱命中日志：任何来源 IP 触碰到任意一个陷阱端口，
  立即写入端口扫描联动日志，由 fail2ban ironwall-portscan 监狱全端口封禁。
- 白名单（静态 + 动态）优先豁免；同一 IP 在保留窗口内只计一次，避免重复累计。

由 install-portscan-guard.sh 安装，root cron 每分钟执行一次。
"""

import json
import os
import re
import time
from datetime import datetime, timedelta, timezone

STATE_FILE = "/www/wwwroot/jdy-cloud/logs/portscan-state.json"
F2B_LOG = "/www/wwwroot/jdy-cloud/logs/ironwall-portscan.log"
DECOY_HIT_LOG = "/www/wwwroot/jdy-cloud/logs/decoy-port-hits.log"
STATIC_WHITELIST = {"203.0.113.10", "203.0.113.11"}
DYNAMIC_WHITELIST_FILE = "/www/wwwroot/jdy-cloud/logs/portscan-dynamic-whitelist.json"
WINDOW_SECONDS = 120
DETECTION_TTL_SECONDS = 6 * 3600
TZ = timezone(timedelta(hours=8))


def load_state():
    try:
        if os.path.isfile(STATE_FILE):
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {"detections": {}, "total_banned": 0, "last_run": ""}


def save_state(state):
    try:
        state["last_run"] = datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S")
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False)
        os.rename(tmp, STATE_FILE)
        os.chmod(STATE_FILE, 0o644)
    except Exception:
        pass


def is_private(ip):
    parts = ip.split(".")
    if len(parts) == 1:
        # 非 IPv4 字面量（如 IPv6/畸形行）：不按私网豁免，交给采集主链判定
        return False
    if parts[0] in ("10", "127") or ip.startswith("192.168.") or ip.startswith("0."):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(parts[1]) <= 31
        except (ValueError, IndexError):
            # IronWall v1.47.7: 畸形第二段不再让 cron 崩溃（安全降级：按公网处理）
            return False
    return False


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


def read_decoy_hits():
    lines = []
    try:
        if os.path.isfile(DECOY_HIT_LOG):
            since = time.time() - WINDOW_SECONDS
            with open(DECOY_HIT_LOG, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        ts = datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S")
                        if ts.timestamp() >= since:
                            lines.append(line)
                    except Exception:
                        continue
    except Exception:
        pass
    return lines


def main():
    state = load_state()
    detections = state.get("detections", {})
    now = time.time()

    # 清理保留窗口之外的旧记录
    detections = {ip: v for ip, v in detections.items()
                  if now - v.get("last_seen", 0) < DETECTION_TTL_SECONDS}

    seen = {}
    for line in read_decoy_hits():
        m = re.search(r"ip=(\S+) port=(\d+)", line)
        if not m:
            continue
        ip = m.group(1)
        if not ip or is_private(ip) or is_whitelisted(ip):
            continue
        port = int(m.group(2))
        seen.setdefault(ip, set()).add(port)

    banned_now = []
    for ip, ports in seen.items():
        entry = detections.get(ip)
        if entry and now - entry.get("last_seen", 0) < DETECTION_TTL_SECONDS:
            # 同一 IP 在保留窗口内只计一次，避免重复累计/重复写日志
            entry["last_seen"] = now
            continue

        with open(F2B_LOG, "a", encoding="utf-8") as f:
            f.write("%s IRONWALL-PORTSCAN ip=%s ports=%s action=BAN\n" %
                    (datetime.now(TZ).strftime("%Y-%m-%dT%H:%M:%S%z"), ip, len(ports)))
        detections[ip] = {"ports": sorted(ports), "last_seen": now}
        banned_now.append(ip)

    state["detections"] = detections
    if banned_now:
        state["total_banned"] = int(state.get("total_banned", 0)) + len(banned_now)
    state["last_banned"] = banned_now[-3:]
    save_state(state)


if __name__ == "__main__":
    main()
