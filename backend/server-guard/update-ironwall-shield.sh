#!/bin/bash
# ============================================================
# IronWall v1.26.0 - Server Shield state collector
# Runs as root cron every minute. Writes a www-readable JSON
# state file consumed by the Java backend (ServerShieldService)
# and shown in the admin security panel.
#
# Usage: bash update-ironwall-shield.sh
# Cron: * * * * * /usr/local/bin/update-ironwall-shield.sh >/dev/null 2>&1
# ============================================================
# Cron PATH may be minimal; ensure /usr/sbin tools are reachable.
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# ---- 管理端口白名单（除 80/443/SSH 外，你主动对外放行的端口；逗号分隔）----
# 用于判定「防火墙放行端口超出白名单」。按你的实际部署填写。
export IRONWALL_ADMIN_PORTS="${IRONWALL_ADMIN_PORTS:-888}"

OUT_FILE="/www/wwwroot/jdy-cloud/logs/server-shield-state.json"
LOG_DIR="$(dirname "$OUT_FILE")"
mkdir -p "$LOG_DIR"
chown www:www "$LOG_DIR" 2>/dev/null || true
chmod 755 "$LOG_DIR" 2>/dev/null || true

if ! command -v python3 >/dev/null 2>&1; then
  echo '{"schema":1,"error":"python3 not found"}' > "$OUT_FILE"
  chown www:www "$OUT_FILE" 2>/dev/null || true
  chmod 644 "$OUT_FILE"
  exit 0
fi

python3 - "$OUT_FILE" <<'PYEOF'
import json, os, re, socket, subprocess, sys
from datetime import datetime, timezone, timedelta

out_file = sys.argv[1]
tz = timezone(timedelta(hours=8))

def run(cmd, timeout=8):
    try:
        r = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=timeout, universal_newlines=True)
        return r.stdout.strip()
    except Exception:
        return ""

def admin_port_set():
    """除 80/443/SSH 外，运维主动对外放行的端口（IRONWALL_ADMIN_PORTS，逗号分隔）。"""
    ports = set()
    for token in os.environ.get("IRONWALL_ADMIN_PORTS", "888").split(","):
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

def f2b_jail(name):
    raw = run("fail2ban-client status %s" % name)
    j = {"name": name, "enabled": False, "available": bool(raw),
         "currently_failed": 0, "total_failed": 0,
         "currently_banned": 0, "total_banned": 0, "banned_ips": []}
    if not raw:
        return j
    j["enabled"] = True
    def num(label):
        m = re.search(label + r":\s*(\d+)", raw)
        return int(m.group(1)) if m else 0
    j["currently_failed"] = num(r"Currently failed")
    j["total_failed"] = num(r"Total failed")
    j["currently_banned"] = num(r"Currently banned")
    j["total_banned"] = num(r"Total banned")
    ips = re.findall(r"(?m)^\s*Banned IP list:\s*(.*)$", raw)
    if ips and ips[0].strip():
        j["banned_ips"] = [x.strip() for x in ips[0].split() if x.strip()]
    return j

def fail2ban():
    status = run("fail2ban-client status")
    running = "Number of jail" in status or "Jail list" in status
    jails = []
    for name in ("ironwall", "sshd", "mysql"):
        jails.append(f2b_jail(name))
    total = sum(j["currently_banned"] for j in jails)
    return {"installed": bool(run("command -v fail2ban-client")),
            "running": running, "jails": jails, "total_banned": total}

def firewall():
    active = False
    backend = "unknown"
    ports = []
    if run("command -v firewall-cmd"):
        backend = "firewalld"
        active = run("firewall-cmd --state") == "running"
        ports = [p for p in re.findall(r"\d+/\w+", run("firewall-cmd --list-ports"))]
    elif run("command -v ufw"):
        backend = "ufw"
        active = "inactive" not in run("ufw status")
    elif run("command -v iptables"):
        backend = "iptables"
        out = run("iptables -L INPUT -n 2>/dev/null")
        active = ("policy DROP" in out) or bool(re.search(r"\b(DROP|REJECT)\b", out))
        ports = sorted(set(re.findall(r"dpt:(\d+)", out)))
    public = set()
    for line in run("ss -ltn 2>/dev/null").splitlines():
        parts = line.split()
        if len(parts) >= 4:
            m = re.search(r":(\d+)$", parts[3])
            if m:
                local = parts[3]
                if local.startswith(("0.0.0.0", "[::]", "*:")):
                    public.add(int(m.group(1)))
    installed = bool(run("command -v firewall-cmd") or run("command -v ufw") or run("command -v iptables"))
    allowed = {80, 443, int(ssh()["port"])}
    admin_ports = admin_port_set()
    decoy_open = set()
    decoy_active = False
    try:
        decoy_data = decoy_ports()
        decoy_active = bool(decoy_data.get("active"))
    except Exception:
        pass
    fw_open = set()
    for p in ports:
        num = p.split("/")[0]
        if num.isdigit():
            fw_open.add(int(num))
    if decoy_active:
        for p in fw_open:
            if 31000 <= p <= 64999:
                decoy_open.add(p)
    expected_open = allowed | admin_ports | decoy_open
    ports_ok = active and fw_open <= expected_open
    unexpected_firewall = sorted(fw_open - expected_open)
    loopback_candidates = sorted((public - fw_open) - allowed)
    return {"installed": installed, "active": active, "backend": backend, "open_ports": sorted(ports),
            "listening_public": sorted(public), "allowed": sorted(allowed),
            "admin_ports": sorted(admin_ports), "fw_open": sorted(fw_open),
            "unexpected_firewall": unexpected_firewall, "loopback_candidates": loopback_candidates,
            "ports_ok": ports_ok}

def ssh():
    out = run("sshd -T 2>/dev/null")
    def val(key, default=""):
        m = re.search(r"(?m)^%s\s+(.+)$" % key, out)
        return m.group(1).strip() if m else default
    try:
        port = int(val("port", "22"))
    except ValueError:
        port = 22
    root_login = val("permitrootlogin", "yes")
    pass_auth = val("passwordauthentication", "yes")
    pubkey = val("pubkeyauthentication", "yes")
    hardened = (root_login in ("no", "prohibit-password", "without-password", "forced-commands-only")
                and pass_auth == "no")
    return {"port": port, "permit_root_login": root_login,
            "password_auth": pass_auth, "pubkey_auth": pubkey,
            "hardened": hardened}

def mysql():
    bind = ""
    for path in ("/etc/my.cnf", "/etc/mysql/my.cnf", "/www/server/data/my.cnf",
                 "/etc/mysql/mysql.conf.d/mysqld.cnf"):
        out = run("grep -E '^\\s*bind-address' %s 2>/dev/null" % path)
        if out:
            bind = out.split("=")[-1].strip()
            break
    if not bind:
        m = re.search(r"127\.0\.0\.1:3306", run("ss -ltn 2>/dev/null"))
        bind = "127.0.0.1" if m else ""
    return {"bind_address": bind or "unknown",
            "local_only": bind in ("127.0.0.1", "localhost")}

def hids():
    present = os.path.isdir("/www/server/panel/plugin/bt_hids") or \
              bool(run("ps -ef 2>/dev/null | grep -i hids | grep -v grep"))
    return {"present": present}

def backup():
    cron = run("crontab -l 2>/dev/null")
    d = run("cat /etc/cron.d/* 2>/dev/null")
    enabled = bool(re.search(r"mysqldump|backup", cron + d, re.I))
    return {"enabled": enabled, "note": "mysqldump 定时备份检测"}

def tamper_proof():
    bt = os.path.isdir("/www/server/panel/data/tamper")
    base = "/www/wwwroot/jdy-cloud/logs/integrity-baseline.sha256"
    state_file = "/www/wwwroot/jdy-cloud/logs/integrity-state.json"
    free = os.path.isfile(base)
    violations = []
    if os.path.isfile(state_file):
        try:
            with open(state_file, "r", encoding="utf-8") as f:
                violations = json.load(f).get("changed", [])
        except Exception:
            pass
    enabled = bt or free
    note = "企业级防篡改保护 /www/wwwroot/jdy-cloud 与站点目录" if bt else "免费文件完整性巡检（基线+定时比对）"
    return {"enabled": enabled, "violations": violations, "note": note}

def nginx_status():
    exposed = False
    files = []
    for f in run("grep -rl 'stub_status' /www/server/nginx/conf/ /www/server/panel/vhost/nginx/ 2>/dev/null").splitlines():
        f = f.strip()
        if not f:
            continue
        files.append(f)
        try:
            with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
            if "stub_status" in text and "deny all" not in text:
                exposed = True
        except Exception:
            pass
    return {"exposed": exposed, "files": files}

def decoy_ports():
    path = "/www/wwwroot/jdy-cloud/logs/decoy-port-state.json"
    hits = 0
    layers = []
    try:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            layers = data.get("layers", []) if isinstance(data, dict) else []
            hits = int(data.get("total_hits", 0) or 0) if isinstance(data, dict) else 0
    except Exception:
        pass
    procs = run("pgrep -f decoy-port-manager.py 2>/dev/null")
    return {"active": bool(procs), "layers": layers, "total_hits": hits, "state_file": path}

def portscan():
    state_file = "/www/wwwroot/jdy-cloud/logs/portscan-state.json"
    total = 0
    active = 0
    try:
        if os.path.isfile(state_file):
            with open(state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            total = int(data.get("total_banned", 0) or 0)
            active = len(data.get("detections", {}) or {})
    except Exception:
        pass
    jail = f2b_jail("ironwall-portscan")
    return {"installed": os.path.isfile(state_file), "detections": active,
            "total_banned": total, "jail": jail, "state_file": state_file}

def warnings(fw, f2b, ssh_conf, my, ng, decoy, ps):
    w = []
    if fw["installed"] and not fw["active"]:
        w.append("防火墙未启用，建议开启系统防火墙并仅放行 80/443")
    if fw.get("unexpected_firewall"):
        w.append("防火墙放行端口超出白名单: %s" % fw["unexpected_firewall"])
    if fw.get("loopback_candidates"):
        w.append("以下服务监听公网网卡但已被防火墙拦截，建议改绑 127.0.0.1: %s" % fw["loopback_candidates"])
    exposed_admin = sorted(set(fw.get("admin_ports", [])) & set(fw.get("fw_open", [])))
    if exposed_admin:
        w.append("管理端口 %s 对所有公网 IP 开放，建议限制来源 IP" % exposed_admin)
    if f2b["installed"] and not f2b["running"]:
        w.append("fail2ban 未运行")
    iron = next((j for j in f2b["jails"] if j["name"] == "ironwall"), None)
    if iron and not iron["enabled"]:
        w.append("ironwall 监狱未启用，网站封禁无法联动全端口封禁")
    if ssh_conf["password_auth"] == "yes":
        w.append("SSH 仍允许密码登录，建议改为密钥登录")
    if not my["local_only"]:
        w.append("MySQL 绑定地址非 127.0.0.1，存在公网暴露风险")
    if ng.get("exposed"):
        w.append("nginx_status 公网可达，建议在 nginx 配置中限定 127.0.0.1/deny all")
    if decoy.get("active") and decoy.get("total_hits", 0) > 0:
        w.append("假端口陷阱已记录 %s 次踩坑，请查看 decoy-port-hits.log" % decoy["total_hits"])
    if ps.get("installed") and not ps.get("jail", {}).get("enabled"):
        w.append("端口扫描检测未接入 fail2ban，建议执行 install-portscan-guard.sh")
    if ps.get("total_banned", 0) > 0:
        w.append("端口扫描检测已全端口封禁 %s 个扫描源" % ps["total_banned"])
    return w

ssh_conf = ssh()
my = mysql()
fw = firewall()
f2b = fail2ban()
ng = nginx_status()
decoy = decoy_ports()
ps = portscan()

state = {
    "schema": 1,
    "generated_at": datetime.now(tz).isoformat(),
    "hostname": socket.gethostname(),
    "engine_version": "v1.26.0",
    "fail2ban": f2b,
    "firewall": fw,
    "ssh": ssh_conf,
    "mysql": my,
    "listening_public": fw["listening_public"],
    "hids": hids(),
    "tamper_proof": tamper_proof(),
    "backup": backup(),
    "nginx_status": ng,
    "decoy_ports": decoy,
    "portscan": ps,
    "warnings": warnings(fw, f2b, ssh_conf, my, ng, decoy, ps),
}

with open(out_file, "w", encoding="utf-8") as f:
    json.dump(state, f, ensure_ascii=False, indent=2)
os.chmod(out_file, 0o644)
try:
    import pwd
    uid = pwd.getpwnam("www").pw_uid
    os.chown(out_file, uid, -1)
except Exception:
    pass
PYEOF

exit 0
