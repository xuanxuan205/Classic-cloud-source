#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
经典云网盘 · 网页安装向导
=============================================================================
把源码上传到服务器后，在浏览器里填几个空，点一下按钮，站点就装好了。

用法（两条路，任选其一）：

  1) 推荐，脚本会顺手把 JDK / MySQL / nginx / Node 装好再起向导：
         sudo bash install.sh --web

  2) 环境已就绪，只想起向导页面：
         sudo python3 installer/web-install.py --repo .

启动后终端会打印一条带访问口令的网址，用浏览器打开即可。
安装完成后向导会自动退出，站点接管 80 端口。

只依赖 Python 3 标准库，不需要 pip 装任何东西。
=============================================================================
"""

import argparse
import html
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

WIZARD_VERSION = "1.0.0"
LOG_LIMIT = 800

# ---------------------------------------------------------------- 全局状态 ---
STATE = {
    "running": False,
    "done": False,
    "ok": False,
    "exit_code": None,
    "started_at": 0.0,
    "result": None,
    "error": "",
}
LOGS = deque(maxlen=LOG_LIMIT)
LOG_LOCK = threading.Lock()
INSTALL_LOCK = threading.Lock()

CONFIG = {
    "repo": os.getcwd(),
    "installer": None,
    "port": 8099,
    "host": "0.0.0.0",
    "token": "",
    "bt": False,
    "bt_java": False,
    "skip_frontend": False,
    "use_prebuild": False,
}


def say(msg=""):
    """向导自己的日志（打到终端，也进网页）"""
    line = "[向导] " + msg if msg else ""
    print(line, flush=True)
    if msg:
        with LOG_LOCK:
            LOGS.append(line)


def push(line):
    with LOG_LOCK:
        LOGS.append(line.rstrip("\n"))


# =============================================================================
#  环境自检
# =============================================================================
def _run(cmd, timeout=10):
    try:
        p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                           text=True, timeout=timeout, errors="replace")
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as exc:  # noqa: BLE001
        return 127, str(exc)


def _which(name):
    return shutil.which(name)


def detect_java():
    exe = _which("java")
    candidates = [exe] if exe else []
    candidates += ["/usr/lib/jvm/default-java/bin/java", "/opt/java/openjdk/bin/java"]
    for c in candidates:
        if not c or not os.path.exists(c):
            continue
        rc, out = _run([c, "-version"])
        m = re.search(r'version "(\d+)', out)
        if m:
            return int(m.group(1)), c
    return 0, ""


def precheck():
    """安装前自检，返回给网页显示"""
    items = []

    def add(name, level, detail):
        items.append({"name": name, "level": level, "detail": detail})

    # Python 自己
    add("Python 运行环境", "ok", "Python %d.%d.%d" % sys.version_info[:3])

    # Java
    major, java_path = detect_java()
    if major == 21:
        add("JDK 21", "ok", java_path)
    elif major:
        add("JDK 21", "warn", "当前是 JDK %d，安装器会自动装 JDK 21" % major)
    else:
        add("JDK 21", "warn", "未检测到，安装器会自动安装")

    # 数据库
    if _which("mysql") or _which("mariadb") or _which("mysqld") or _which("mariadbd"):
        add("数据库", "ok", "已安装 MySQL / MariaDB 客户端")
    else:
        add("数据库", "warn", "未检测到，安装器会自动安装 MySQL 8")

    # nginx
    if _which("nginx") or os.path.exists("/www/server/nginx/sbin/nginx"):
        add("nginx", "ok", "已安装")
    else:
        add("nginx", "warn", "未检测到，安装器会自动安装")

    # 前端编译工具
    node = _which("node")
    if node:
        rc, out = _run([node, "-v"])
        add("Node.js", "ok", out.strip())
    else:
        add("Node.js", "warn", "未检测到，安装器会自动安装 Node 20（用于编译前端）")

    # 磁盘
    try:
        st = os.statvfs("/")
        free_gb = st.f_bavail * st.f_frsize / 1024 / 1024 / 1024
        level = "ok" if free_gb >= 5 else "warn"
        add("磁盘剩余", level, "%.1f GB" % free_gb)
    except Exception:  # noqa: BLE001
        add("磁盘剩余", "warn", "无法读取")

    # 是否已经装过
    conf = os.path.join(os.environ.get("JDY_ETC", "/etc/jdy-cloud"), "install.conf")
    if os.path.exists(conf):
        add("已有安装", "warn", "本机之前装过一次，重新安装会覆盖站点配置（数据不受影响）")
    else:
        add("已有安装", "ok", "干净的服务器，可以开始")

    # 宝塔
    if os.path.isdir("/www/server/panel"):
        add("宝塔面板", "ok", "已识别，将按宝塔目录结构部署")
        bt_home = "/www/server/java"
        if os.path.isdir(bt_home):
            try:
                names = sorted(d for d in os.listdir(bt_home)
                               if os.path.isdir(os.path.join(bt_home, d)))
            except OSError:
                names = []
            if names:
                add("宝塔 Java 项目管理器", "ok", "已装 JDK：" + "、".join(names[:4]))

    return items


# =============================================================================
#  真正干活：调用 install.sh 全自动部署
# =============================================================================
def build_install_command(form):
    repo = CONFIG["repo"]
    installer = CONFIG["installer"] or os.path.join(repo, "install.sh")
    cmd = ["bash", installer, "--yes"]

    domain = (form.get("domain") or "").strip()
    if domain:
        cmd += ["--domain", domain]
    else:
        cmd += ["--no-domain"]

    def put(flag, key):
        nonlocal cmd
        value = (form.get(key) or "").strip()
        if value:
            cmd += [flag, value]

    put("--site-name", "site_name")
    put("--site-short", "site_short")
    put("--contact-email", "contact_email")
    put("--admin-user", "admin_user")
    put("--admin-pass", "admin_pass")
    put("--admin-email", "admin_email")
    put("--db-name", "db_name")
    put("--db-user", "db_user")
    put("--db-pass", "db_pass")
    put("--port", "server_port")
    put("--max-file-size", "max_file_size")

    if domain and not form.get("enable_ssl", True):
        cmd += ["--no-ssl"]
    if CONFIG["skip_frontend"] or form.get("skip_frontend"):
        cmd += ["--skip-frontend"]
    if CONFIG["use_prebuild"] or form.get("use_prebuild"):
        cmd += ["--use-prebuild"]
    if CONFIG["bt_java"] or form.get("bt_java"):
        cmd += ["--bt-java"]
    elif CONFIG["bt"] or form.get("bt"):
        cmd += ["--bt"]
    return cmd


def run_install(form):
    global STATE
    with INSTALL_LOCK:
        if STATE["running"]:
            return
        STATE.update(running=True, done=False, ok=False, exit_code=None,
                     started_at=time.time(), result=None, error="")
        with LOG_LOCK:
            LOGS.clear()

    try:
        cmd = build_install_command(form)
        env = dict(os.environ)
        env["PYTHONUNBUFFERED"] = "1"
        root_pw = (form.get("mysql_root_password") or "").strip()
        if root_pw:
            env["MYSQL_ROOT_PASSWORD"] = root_pw

        push("$ " + " ".join(cmd))
        push("")

        proc = subprocess.Popen(
            cmd, cwd=CONFIG["repo"], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, env=env, bufsize=1,
        )
        assert proc.stdout is not None
        for raw in proc.stdout:
            push(raw.decode("utf-8", errors="replace"))
        code = proc.wait()
    except Exception as exc:  # noqa: BLE001
        push("\n[向导] 执行安装器失败：%s" % exc)
        code = 127

    result = read_result()
    STATE.update(running=False, done=True, exit_code=code,
                 ok=(code == 0), result=result)
    if code == 0:
        push("")
        push("[向导] 安装完成，站点已经可以访问。")
    else:
        push("")
        push("[向导] 安装未完成（退出码 %s），请把上面的报错交给技术支持。" % code)


def read_result():
    etc = os.environ.get("JDY_ETC", "/etc/jdy-cloud")
    for path in (os.path.join(etc, "install-result.json"),
                 "/etc/jdy-cloud/install-result.json"):
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as fh:
                    return json.load(fh)
        except Exception:  # noqa: BLE001
            continue
    return None


# =============================================================================
#  HTTP 服务
# =============================================================================
LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class Handler(BaseHTTPRequestHandler):
    server_version = "JDY-Install-Wizard/" + WIZARD_VERSION

    # ------------------------------------------------------------- 工具方法 ---
    def log_message(self, fmt, *args):
        pass  # 静音，避免刷屏；需要排查时把下面这行放开
        # sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _token_ok(self, query):
        if not CONFIG["token"]:
            return True
        given = query.get("t", [""])[0] or self.headers.get("X-Install-Token", "")
        if given and secrets.compare_digest(given, CONFIG["token"]):
            return True
        cookie = self.headers.get("Cookie", "")
        if CONFIG["token"] in cookie:
            return True
        return False

    def _json(self, payload, code=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, text, code=200):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _denied(self):
        self._html(
            "<!doctype html><meta charset='utf-8'>"
            "<body style='background:#0f172a;color:#e2e8f0;font-family:sans-serif;"
            "padding:60px;text-align:center'>"
            "<h2>需要访问口令</h2>"
            "<p style='color:#94a3b8'>请使用终端里打印的那条完整网址打开本页面。</p>"
            "</body>", 403)

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        try:
            return json.loads(raw)
        except Exception:  # noqa: BLE001
            return {}

    def _client_host(self):
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or ""
        host = host.split(",")[0].strip()
        return host.split(":")[0].strip()

    # ------------------------------------------------------------------ 路由 ---
    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        path = parsed.path.rstrip("/") or "/"

        if not self._token_ok(query):
            self._denied()
            return

        if path == "/":
            self._html(render_page(), 200)
            return

        if path == "/api/state":
            host = self._client_host()
            docker_like = os.path.exists("/.dockerenv")
            self._json({
                "version": WIZARD_VERSION,
                "bt": CONFIG["bt"] or os.path.isdir("/www/server/panel"),
                "bt_java": CONFIG["bt_java"] or (
                    os.path.isdir("/www/server/panel") and os.path.isdir("/www/server/java")),
                "repo": CONFIG["repo"],
                "detected_host": "" if host in LOOPBACK else host,
                "precheck": precheck(),
                "running": STATE["running"],
                "installed": os.path.exists("/etc/jdy-cloud/install.conf"),
                "vm_warning": docker_like,
            })
            return

        if path == "/api/log":
            try:
                cursor = int(query.get("cursor", ["0"])[0])
            except ValueError:
                cursor = 0
            with LOG_LOCK:
                lines = list(LOGS)
            if cursor > len(lines):
                cursor = 0
            self._json({
                "lines": lines[cursor:],
                "cursor": len(lines),
                "running": STATE["running"],
                "done": STATE["done"],
                "ok": STATE["ok"],
                "exit_code": STATE["exit_code"],
                "result": STATE["result"],
                "elapsed": int(time.time() - STATE["started_at"]) if STATE["started_at"] else 0,
            })
            return

        self._json({"error": "not found"}, 404)

    def do_POST(self):  # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        path = parsed.path.rstrip("/") or "/"

        if not self._token_ok(query):
            self._json({"error": "口令不正确"}, 403)
            return

        if path == "/api/install":
            if STATE["running"]:
                self._json({"error": "安装正在进行中"}, 409)
                return
            form = self._read_body()
            missing = validate(form)
            if missing:
                self._json({"error": "请填写：" + "、".join(missing)}, 400)
                return
            threading.Thread(target=run_install, args=(form,), daemon=True).start()
            self._json({"started": True})
            return

        if path == "/api/quit":
            self._json({"bye": True})
            threading.Thread(target=self._shutdown_later, daemon=True).start()
            return

        self._json({"error": "not found"}, 404)

    def _shutdown_later(self):
        time.sleep(0.4)
        say("收到关闭指令，向导退出。")
        os._exit(0)


def validate(form):
    missing = []
    if not (form.get("admin_user") or "").strip():
        missing.append("管理员账号")
    password = (form.get("admin_pass") or "").strip()
    if len(password) < 8:
        missing.append("管理员密码（至少 8 位）")
    if not (form.get("db_name") or "").strip():
        missing.append("数据库名")
    if not (form.get("db_user") or "").strip():
        missing.append("数据库用户名")
    if not (form.get("db_pass") or "").strip():
        missing.append("数据库密码")
    domain = (form.get("domain") or "").strip()
    if domain and not re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", domain):
        missing.append("域名（格式不对，不要带 http://）")
    return missing


# =============================================================================
#  网页界面
# =============================================================================
PAGE_TEMPLATE = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>安装向导 · 经典云网盘</title>
<style>
  :root{
    --bg:#0f172a; --panel:#151f36; --panel2:#1c2742;
    --line:#27334f; --text:#e2e8f0; --dim:#93a2bd; --accent:#6366f1;
    --ok:#34d399; --warn:#fbbf24; --err:#f87171;
  }
  *{box-sizing:border-box}
  body{margin:0;background:radial-gradient(1200px 600px at 50% -10%,#1e2a4a 0%,var(--bg) 55%);
       color:var(--text);font:15px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;
       min-height:100vh;padding:40px 16px 80px}
  .wrap{max-width:840px;margin:0 auto}
  .brand{display:flex;align-items:center;gap:14px;margin-bottom:6px}
  .logo{width:46px;height:46px;border-radius:13px;background:linear-gradient(135deg,#6366f1,#8b5cf6);
        display:flex;align-items:center;justify-content:center;font-size:22px}
  h1{font-size:21px;margin:0;font-weight:650;letter-spacing:.3px}
  .sub{color:var(--dim);font-size:13px;margin:0 0 26px 60px}
  .steps{display:flex;gap:8px;margin:0 0 22px 60px}
  .dot{display:flex;align-items:center;gap:7px;font-size:12.5px;color:var(--dim)}
  .dot i{width:20px;height:20px;border-radius:50%;background:var(--panel2);border:1px solid var(--line);
         display:flex;align-items:center;justify-content:center;font-style:normal;font-size:11px}
  .dot.on{color:#c7d2fe}
  .dot.on i{background:var(--accent);border-color:var(--accent);color:#fff}
  .dot.done i{background:var(--ok);border-color:var(--ok);color:#04231a}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:24px;margin-bottom:16px}
  .card h2{font-size:15px;margin:0 0 4px;font-weight:600}
  .card .hint{color:var(--dim);font-size:13px;margin:0 0 18px}
  .row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
  .row.one{grid-template-columns:1fr}
  @media(max-width:640px){.row{grid-template-columns:1fr}}
  label{display:block;font-size:12.5px;color:var(--dim);margin:0 0 6px}
  input,select{width:100%;padding:10px 12px;border-radius:10px;border:1px solid var(--line);
        background:#101a2f;color:var(--text);font-size:14px;outline:none;font-family:inherit}
  input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(99,102,241,.16)}
  .field{margin-bottom:14px}
  .field .tip{font-size:11.5px;color:#6f7f9b;margin-top:5px}
  .inline{display:flex;gap:8px}
  .inline input{flex:1}
  button{border:0;border-radius:10px;padding:11px 18px;font-size:14px;cursor:pointer;
         font-family:inherit;font-weight:600;transition:.15s}
  .primary{background:linear-gradient(135deg,#6366f1,#7c5cf6);color:#fff;width:100%;padding:14px;font-size:15px}
  .primary:hover{filter:brightness(1.08)}
  .primary:disabled{opacity:.5;cursor:not-allowed;filter:none}
  .ghost{background:var(--panel2);color:var(--text);border:1px solid var(--line);padding:9px 14px;font-size:13px}
  .ghost:hover{border-color:var(--accent)}
  .chk{display:flex;align-items:center;gap:9px;font-size:13px;color:var(--dim);cursor:pointer}
  .chk input{width:auto}
  ul.checks{list-style:none;margin:0;padding:0}
  ul.checks li{display:flex;gap:10px;align-items:flex-start;padding:7px 0;border-bottom:1px dashed #202c47;font-size:13.5px}
  ul.checks li:last-child{border-bottom:0}
  ul.checks .tag{flex:0 0 62px;font-size:11.5px;padding:2px 0;text-align:center;border-radius:6px}
  .t-ok{background:rgba(52,211,153,.14);color:var(--ok)}
  .t-warn{background:rgba(251,191,36,.14);color:var(--warn)}
  .t-err{background:rgba(248,113,113,.14);color:var(--err)}
  ul.checks .what{flex:0 0 116px;color:var(--text)}
  ul.checks .detail{color:var(--dim);word-break:break-all;font-size:12.5px}
  #console{background:#0a1120;border:1px solid var(--line);border-radius:12px;padding:14px;
           font:12.5px/1.65 "SFMono-Regular",Consolas,"Liberation Mono",monospace;
           height:340px;overflow:auto;white-space:pre-wrap;word-break:break-all;color:#c9d6ea}
  #console .ok{color:var(--ok)} #console .bad{color:var(--err)}
  .bar{height:4px;background:var(--panel2);border-radius:4px;overflow:hidden;margin:14px 0 12px}
  .bar>i{display:block;height:100%;width:30%;background:linear-gradient(90deg,#6366f1,#a78bfa);
         animation:slide 1.4s ease-in-out infinite}
  @keyframes slide{0%{margin-left:-30%}100%{margin-left:100%}}
  .result-url{display:flex;align-items:center;gap:10px;background:#101a2f;border:1px solid var(--line);
              border-radius:11px;padding:12px 14px;margin-bottom:10px}
  .result-url .k{flex:0 0 74px;color:var(--dim);font-size:12.5px}
  .result-url .v{flex:1;word-break:break-all;font-size:13.5px}
  .result-url a{color:#a5b4fc;text-decoration:none}
  .result-url a:hover{text-decoration:underline}
  .kv{display:flex;gap:10px;padding:9px 0;border-bottom:1px dashed #202c47;font-size:13.5px}
  .kv:last-child{border-bottom:0}
  .kv .k{flex:0 0 74px;color:var(--dim)}
  .kv .v{flex:1;font-family:Consolas,monospace;word-break:break-all}
  .btcard{border:1px solid var(--line);border-radius:12px;overflow:hidden;margin-top:10px;background:#101a2f}
  .btrow{display:grid;grid-template-columns:132px 1fr;gap:12px;padding:10px 14px;border-bottom:1px solid #202c47;font-size:13.5px}
  .btrow:last-child{border-bottom:0}
  .btrow .k{color:var(--dim)}
  .btrow .v{color:#c7d2fe;font-family:Consolas,monospace;word-break:break-all;white-space:pre-wrap}
  @media (max-width:640px){.btrow{grid-template-columns:1fr;gap:4px}}
  .banner{border-radius:12px;padding:13px 16px;font-size:13.5px;margin-bottom:16px}
  .banner.warn{background:rgba(251,191,36,.1);border:1px solid rgba(251,191,36,.3);color:#fde68a}
  .banner.err{background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.32);color:#fecaca}
  .banner.ok{background:rgba(52,211,153,.1);border:1px solid rgba(52,211,153,.3);color:#a7f3d0}
  .hide{display:none}
  .foot{color:#5b6b87;font-size:12px;text-align:center;margin-top:26px}
  .spin{display:inline-block;width:13px;height:13px;border:2px solid rgba(255,255,255,.35);
        border-top-color:#fff;border-radius:50%;animation:sp .7s linear infinite;vertical-align:-2px;margin-right:8px}
  @keyframes sp{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="wrap">
  <div class="brand"><div class="logo">☁</div><h1>经典云网盘 · 安装向导</h1></div>
  <p class="sub">填几个空，点一下按钮，剩下的交给它。</p>
  <div class="steps">
    <div class="dot on" id="d1"><i>1</i>环境自检</div>
    <div class="dot" id="d2"><i>2</i>填写配置</div>
    <div class="dot" id="d3"><i>3</i>自动部署</div>
    <div class="dot" id="d4"><i>4</i>完成</div>
  </div>

  <div id="alert"></div>

  <!-- 步骤一 -->
  <div class="card" id="step1">
    <h2>环境自检</h2>
    <p class="hint">正在检查这台服务器是否具备安装条件……</p>
    <ul class="checks" id="checks"><li><span class="detail">检查中…</span></li></ul>
    <div style="margin-top:18px">
      <button class="primary" id="btn-next" disabled><span class="spin"></span>检查中…</button>
    </div>
  </div>

  <!-- 步骤二 -->
  <div class="card hide" id="step2">
    <h2>站点与管理员</h2>
    <p class="hint">带 <span style="color:#818cf8">*</span> 的是必填。不确定的保持默认即可。</p>

    <div class="field">
      <label>站点域名（有域名就填，没有留空，之后用服务器 IP 访问）</label>
      <input id="f-domain" placeholder="例如 drive.example.com">
      <div class="tip">不要带 https:// 和结尾斜杠</div>
    </div>
    <div class="row">
      <div class="field"><label>站点名称</label><input id="f-site_name" value="我的网盘"></div>
      <div class="field"><label>站点简称（2-6 个字）</label><input id="f-site_short" value="我的云"></div>
    </div>
    <div class="field"><label>对外联系邮箱（可留空）</label><input id="f-contact_email" placeholder="support@example.com"></div>

    <h2 style="margin-top:26px">管理员账号</h2>
    <p class="hint">装好后用它登录后台，请务必记下来。</p>
    <div class="row">
      <div class="field"><label><span style="color:#818cf8">*</span> 管理员账号</label><input id="f-admin_user" value="admin"></div>
      <div class="field">
        <label><span style="color:#818cf8">*</span> 管理员密码（至少 8 位）</label>
        <div class="inline">
          <input id="f-admin_pass" placeholder="留空则自动生成强密码">
          <button class="ghost" type="button" onclick="rollPassword()">随机</button>
        </div>
      </div>
    </div>
    <div class="field"><label>管理员邮箱（收申诉与告警通知，可留空）</label><input id="f-admin_email"></div>

    <h2 style="margin-top:26px">数据库</h2>
    <p class="hint">安装向导会自动建库建账号并把表建好，你只要定个名字和密码。</p>
    <div class="row">
      <div class="field"><label><span style="color:#818cf8">*</span> 数据库名</label><input id="f-db_name" value="jdy_cloud"></div>
      <div class="field"><label><span style="color:#818cf8">*</span> 数据库用户名</label><input id="f-db_user" value="jdy_cloud"></div>
    </div>
    <div class="row">
      <div class="field">
        <label><span style="color:#818cf8">*</span> 数据库密码</label>
        <div class="inline">
          <input id="f-db_pass" placeholder="留空则自动生成">
          <button class="ghost" type="button" onclick="rollDb()">随机</button>
        </div>
      </div>
      <div class="field">
        <label>MySQL root 密码（仅当你的数据库设置过 root 密码时才填）</label>
        <input id="f-mysql_root_password" type="password" placeholder="宝塔新建的机器通常留空即可">
      </div>
    </div>

    <h2 style="margin-top:26px">运行参数</h2>
    <div class="row">
      <div class="field"><label>后端端口（只监听本机，改不改都行）</label><input id="f-server_port" value="15060"></div>
      <div class="field"><label>单个文件最大多少 MB</label><input id="f-max_file_size" value="850"></div>
    </div>
    <div class="field">
      <label class="chk"><input type="checkbox" id="f-enable_ssl" checked> 自动申请 HTTPS 证书（需要域名已解析到这台服务器）</label>
    </div>
    <div class="field">
      <label class="chk"><input type="checkbox" id="f-use_prebuild"> 使用仓库里已编译好的前端（服务器上不再装 Node 编译）</label>
    </div>
    <div class="field">
      <label class="chk"><input type="checkbox" id="f-bt_java"> 后端改用宝塔「Java 项目管理器」托管（装了宝塔才勾）</label>
      <div class="tip">勾了之后不再写 systemd 服务，开机自启交给面板；装完会列出「添加 Java 项目」对话框每一项该填什么。
        域名、HTTPS 仍然由本次安装配好的站点接管。</div>
    </div>

    <div style="margin-top:22px">
      <button class="primary" id="btn-install">开始安装</button>
    </div>
  </div>

  <!-- 步骤三 -->
  <div class="card hide" id="step3">
    <h2 id="progress-title">正在安装…</h2>
    <p class="hint" id="progress-hint">装依赖、建数据库、编译前后端、配置站点，全程自动。首次约 5-15 分钟，请不要关掉这个页面。</p>
    <div class="bar"><i></i></div>
    <div id="console"></div>
  </div>

  <!-- 步骤四 -->
  <div class="card hide" id="step4">
    <h2>🎉 安装完成</h2>
    <p class="hint">站点已经跑起来了，下面这些信息请立刻保存好。</p>
    <div id="result-body"></div>
    <div style="margin-top:20px;display:flex;gap:10px;flex-wrap:wrap">
      <button class="ghost" onclick="copyAll()">复制全部信息</button>
      <button class="ghost" onclick="quitWizard()">关闭向导</button>
    </div>
    <p class="hint" style="margin-top:16px">安全起见，装完后建议关掉这个向导进程（点上面的「关闭向导」，或在终端按 Ctrl+C）。</p>
  </div>

  <div class="foot">经典云网盘 · 网页安装向导 v__VERSION__</div>
</div>

<script>
const TOKEN = new URLSearchParams(location.search).get('t') || sessionStorage.getItem('jdy-t') || '';
sessionStorage.setItem('jdy-t', TOKEN);
const api = (p) => p + (p.includes('?') ? '&' : '?') + 't=' + encodeURIComponent(TOKEN);
const H = () => ({'Content-Type': 'application/json', 'X-Install-Token': TOKEN});
const $ = (id) => document.getElementById(id);

let cursor = 0, polling = false;

function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));}
function rand(n){const a='abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789';let s='';const u=new Uint32Array(n);crypto.getRandomValues(u);for(let i=0;i<n;i++)s+=a[u[i]%a.length];return s;}
function btRow(k,v){return '<div class="btrow"><span class="k">'+esc(k)+'</span><span class="v">'+esc(v==null?'':v)+'</span></div>';}
function rollPassword(){$('f-admin_pass').value = rand(6).toUpperCase()+rand(8)+Math.floor(Math.random()*90+10);}
function rollDb(){$('f-db_pass').value = rand(20);}

function setStep(n){
  const on=$('d'+n);
  for(let i=1;i<=4;i++){const d=$('d'+i);d.classList.remove('on');if(i<n)d.classList.add('done');else d.classList.remove('done');}
  on.classList.add('on');
  for(let i=1;i<=4;i++)$('step'+i).classList.toggle('hide', i!==n);
}
function banner(cls,text){$('alert').innerHTML = text ? '<div class="banner '+cls+'">'+text+'</div>' : '';}

async function loadState(){
  try{
    const r = await fetch(api('/api/state'), {headers:H()});
    if(!r.ok){banner('err','访问口令不对，请用终端里打印的完整网址打开本页。');return;}
    const s = await r.json();
    // 自检结果
    $('checks').innerHTML = s.precheck.map(it =>
      '<li><span class="tag t-'+it.level+'">'+({ok:'通过',warn:'注意',err:'失败'}[it.level]||it.level)+'</span>'
      +'<span class="what">'+esc(it.name)+'</span><span class="detail">'+esc(it.detail)+'</span></li>').join('');
    const bad = s.precheck.filter(it=>it.level==='err').length;
    $('btn-next').disabled = bad>0;
    $('btn-next').innerHTML = bad>0 ? '有项目未通过，请先处理' : '下一步';
    if(s.detected_host && !$('f-domain').value) $('f-domain').value = s.detected_host;
    if(s.installed) banner('warn','这台服务器之前装过一次。继续安装会覆盖站点配置，数据库和已上传的文件不受影响。');
    if(s.vm_warning) banner('warn','检测到容器环境，部分系统操作可能受限。建议在真实服务器上部署。');
    if(s.bt_java) $('f-bt_java').checked = true;
  }catch(e){
    banner('err','无法读取服务器状态：'+esc(e.message||e));
    $('btn-next').disabled = true;
    return;
  }
  await resume();
}

// 刷新页面时：安装中→回到进度页；已装完→直接显示结果页；填过表→回到表单
async function resume(){
  if(location.hash==='#form'){
    setStep(2);
    if(!$('f-admin_pass').value) rollPassword();
    return;
  }
  try{
    const r = await fetch(api('/api/log?cursor=0'), {headers:H()});
    const s = await r.json();
    if(s.result && s.ok){ cursor = s.cursor; showResult(s.result); return; }
    if(s.running){ cursor = s.cursor; setStep(3); poll(); return; }
  }catch(e){}
  if(sessionStorage.getItem('jdy-step')==='2'){
    setStep(2);
    if(!$('f-admin_pass').value) rollPassword();
  }
}

async function startInstall(){
  const form = {
    domain: $('f-domain').value.trim(),
    site_name: $('f-site_name').value.trim(),
    site_short: $('f-site_short').value.trim(),
    contact_email: $('f-contact_email').value.trim(),
    admin_user: $('f-admin_user').value.trim(),
    admin_pass: $('f-admin_pass').value.trim() || $('f-admin_pass').placeholder.replace('留空则自动生成强密码',''),
    admin_email: $('f-admin_email').value.trim(),
    db_name: $('f-db_name').value.trim(),
    db_user: $('f-db_user').value.trim(),
    db_pass: $('f-db_pass').value.trim(),
    mysql_root_password: $('f-mysql_root_password').value,
    server_port: $('f-server_port').value.trim(),
    max_file_size: $('f-max_file_size').value.trim(),
    enable_ssl: $('f-enable_ssl').checked,
    use_prebuild: $('f-use_prebuild').checked,
    bt_java: $('f-bt_java').checked
  };
  if(!form.admin_pass){rollPassword();form.admin_pass=$('f-admin_pass').value;}
  if(!form.db_pass){rollDb();form.db_pass=$('f-db_pass').value;}

  $('btn-install').disabled = true;
  $('btn-install').innerHTML = '<span class="spin"></span>正在安装…';
  const r = await fetch(api('/api/install'), {method:'POST', headers:H(), body:JSON.stringify(form)});
  if(!r.ok){
    const e = await r.json().catch(()=>({}));
    banner('err', esc(e.error||'启动安装失败'));
    $('btn-install').disabled = false;
    $('btn-install').textContent = '开始安装';
    return;
  }
  banner('',''); setStep(3); cursor = 0; poll();
}

async function poll(){
  if(polling) return; polling = true;
  try{
    const r = await fetch(api('/api/log?cursor='+cursor), {headers:H()});
    const s = await r.json();
    cursor = s.cursor;
    if(s.lines && s.lines.length){
      const box = $('console');
      const atBottom = box.scrollTop + box.clientHeight >= box.scrollHeight - 30;
      s.lines.forEach(l=>{
        const cls = l.includes('✗') ? 'bad' : (l.includes('✓')||l.includes('成功') ? 'ok' : '');
        box.insertAdjacentHTML('beforeend','<span class="'+cls+'">'+esc(l)+'\n</span>');
      });
      if(atBottom) box.scrollTop = box.scrollHeight;
    }
    $('progress-title').textContent = '正在安装… 已用时 ' + s.elapsed + ' 秒';
    if(s.running){ polling=false; setTimeout(poll, 900); return; }
    if(s.done){
      polling=false;
      if(s.ok){ showResult(s.result); }
      else {
        $('progress-title').textContent = '安装中断';
        $('progress-hint').textContent = '请把上面的报错交给技术支持；修好后刷新本页可以重试。';
        banner('err','安装没有完成（退出码 '+s.exit_code+'）。常见原因：数据库密码不对、网络下载依赖失败、磁盘空间不足。');
      }
      return;
    }
    polling=false; setTimeout(poll, 900);
  }catch(e){
    polling=false; setTimeout(poll, 1500);
  }
}

let LAST_RESULT = null;
function showResult(res){
  LAST_RESULT = res || {};
  const r = LAST_RESULT;
  sessionStorage.removeItem('jdy-step');
  setStep(4);
  const url = r.site_url || '';
  let body = '';
  if(url){
    body += '<div class="result-url"><span class="k">首页地址</span><span class="v"><a href="'+esc(url)+'" target="_blank" rel="noopener">'+esc(url)+'</a></span></div>';
    body += '<div class="result-url"><span class="k">后台地址</span><span class="v"><a href="'+esc(r.admin_url||url+'/admin')+'" target="_blank" rel="noopener">'+esc(r.admin_url||url+'/admin')+'</a></span></div>';
  } else {
    body += '<div class="banner warn">没能自动识别出访问地址，请用浏览器打开服务器 IP 或你的域名。</div>';
  }
  body += '<div style="margin-top:14px">'
       +  '<div class="kv"><span class="k">管理员</span><span class="v">'+esc(r.admin_username||'')+'</span></div>'
       +  '<div class="kv"><span class="k">密码</span><span class="v">'+esc(r.admin_password||'')+'</span></div>'
       +  '</div>';
  body += '<div style="margin-top:18px">'
       +  '<div class="kv"><span class="k">站点目录</span><span class="v">'+esc(r.web_root||'')+'</span></div>'
       +  '<div class="kv"><span class="k">配置文件</span><span class="v">'+esc(r.config_file||'')+'</span></div>'
       +  '<div class="kv"><span class="k">程序目录</span><span class="v">'+esc(r.app_dir||'')+'</span></div>'
       +  '</div>';
  if(r.bt_java && r.bt_java.enabled){
    const b = r.bt_java;
    body += '<div style="margin-top:26px">'
         +  '<h2 style="margin:0 0 6px">还差一步：去宝塔面板添加 Java 项目</h2>'
         +  '<p class="hint" style="margin:0 0 10px">打开「'+esc(b.panel_path||'网站 → Java 项目 → 添加 Java 项目')+'」，照着下表填，然后点「启动」。</p>'
         +  '<div class="btcard">'
         +  btRow('项目类型', b.project_type)
         +  btRow('项目路径', b.project_path)
         +  btRow('接管原项目', b.takeover)
         +  btRow('项目名称', b.project_name)
         +  btRow('项目 JDK', b.jdk)
         +  btRow('启动命令', b.start_command)
         +  btRow('项目端口', b.port)
         +  btRow('绑定域名', b.domain_field)
         +  btRow('环境变量（更多配置）', (b.env||[]).join('\n'))
         +  btRow('只认 java 命令时', b.fallback_command)
         +  '</div>'
         +  '<div class="banner warn" style="margin-top:14px">'
         +  esc(b.why_start_script||'启动命令请用上面那条 start.sh，它会先载入配置文件再拉 Java；直接 java -jar 会缺配置起不来。')
         +  '</div>'
         +  '<p class="hint">面板里记得把「开机自启」勾上，重启服务器后站点会自动恢复。</p>'
         +  '</div>';
  }
  if(!r.ssl && r.domain){
    body += '<div class="banner warn" style="margin-top:16px">还没上 HTTPS。域名解析生效后，在终端执行：'
         +  'certbot --nginx -d '+esc(r.domain)+'</div>';
  }
  $('result-body').innerHTML = body;
}

function copyAll(){
  const r = LAST_RESULT||{};
  const lines = ['经典云网盘',
    '首页：'+(r.site_url||''),
    '后台：'+(r.admin_url||''),
    '管理员：'+(r.admin_username||''),
    '密码：'+(r.admin_password||'')
  ];
  if(r.bt_java && r.bt_java.enabled){
    const b = r.bt_java;
    lines.push('');
    lines.push('宝塔「添加 Java 项目」填写卡：');
    lines.push('  项目类型：'+(b.project_type||''));
    lines.push('  项目路径：'+(b.project_path||''));
    lines.push('  接管原项目：'+(b.takeover||''));
    lines.push('  项目名称：'+(b.project_name||''));
    lines.push('  项目 JDK：'+(b.jdk||''));
    lines.push('  启动命令：'+(b.start_command||''));
    lines.push('  项目端口：'+(b.port||''));
    lines.push('  绑定域名：'+(b.domain_field||''));
    lines.push('  环境变量：'+((b.env||[]).join('   ')));
  }
  const text = lines.join('\n');
  navigator.clipboard?.writeText(text).then(
    ()=>banner('ok','已复制到剪贴板，请粘贴到安全的地方保存。'),
    ()=>banner('warn','浏览器不允许自动复制，请手动选中上面的信息。'));
}

async function quitWizard(){
  if(!confirm('确定关闭向导进程吗？站点不受影响，只是这个安装页面会消失。')) return;
  try{ await fetch(api('/api/quit'), {method:'POST', headers:H()}); }catch(e){}
  banner('ok','向导已关闭，直接访问你的站点即可。');
  setStep(4);
}

$('btn-next').addEventListener('click', ()=>{ sessionStorage.setItem('jdy-step','2'); setStep(2); if(!$('f-admin_pass').value) rollPassword(); });
$('btn-install').addEventListener('click', startInstall);
loadState();

if(location.search.indexOf('t=')>=0){
  history.replaceState(null,'',location.pathname + location.hash);
}
</script>
</body>
</html>
"""


def render_page():
    return PAGE_TEMPLATE.replace("__VERSION__", WIZARD_VERSION)


# =============================================================================
#  启动
# =============================================================================
def parse_args():
    ap = argparse.ArgumentParser(description="经典云网盘 · 网页安装向导")
    ap.add_argument("--repo", default=os.getcwd(), help="源码仓库目录")
    ap.add_argument("--installer", default=None, help="install.sh 路径")
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--bt", action="store_true", help="宝塔面板模式")
    ap.add_argument("--bt-java", action="store_true",
                    help="宝塔「Java 项目管理器」托管模式（隐含 --bt，不写 systemd）")
    ap.add_argument("--skip-frontend", action="store_true")
    ap.add_argument("--use-prebuild", action="store_true")
    ap.add_argument("--token", default=None, help="自定义访问口令；默认随机生成")
    ap.add_argument("--loopback", action="store_true", help="只监听本机，方便配合 nginx 反代")
    return ap.parse_args()


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:  # noqa: BLE001
        return "127.0.0.1"
    finally:
        s.close()


def main():
    args = parse_args()
    if args.loopback:
        args.host = "127.0.0.1"

    CONFIG.update(
        repo=os.path.abspath(args.repo),
        installer=os.path.abspath(args.installer) if args.installer else None,
        port=args.port,
        host=args.host,
        bt=args.bt or os.path.isdir("/www/server/panel"),
        bt_java=args.bt_java,
        skip_frontend=args.skip_frontend,
        use_prebuild=args.use_prebuild,
    )

    if not os.path.exists(os.path.join(CONFIG["repo"], "backend", "pom.xml")):
        print("找不到项目源码：%s 下没有 backend/pom.xml" % CONFIG["repo"], file=sys.stderr)
        print("请用 --repo 指定源码目录。", file=sys.stderr)
        return 1

    # 访问口令：显式指定 > 非本机监听时随机生成 > 本机监听时不设
    if args.token:
        CONFIG["token"] = args.token
    elif args.host in LOOPBACK:
        CONFIG["token"] = ""
    else:
        CONFIG["token"] = secrets.token_hex(8)

    display = "127.0.0.1" if args.host in LOOPBACK else lan_ip()

    url = "http://%s:%d/?t=%s" % (display, args.port, CONFIG["token"])
    if not CONFIG["token"]:
        url = "http://%s:%d/" % (display, args.port)

    print("")
    print("  ============================================================")
    print("      经典云网盘 · 网页安装向导已启动")
    print("  ============================================================")
    print("")
    print("      请在浏览器里打开下面这条网址（含访问口令）：")
    print("")
    print("          %s" % url)
    print("")
    print("      源码目录：%s" % CONFIG["repo"])
    print("      口令只显示这一次，装完后向导会自动退出。")
    print("      中止：Ctrl+C")
    print("")
    sys.stdout.flush()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.daemon_threads = True
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n向导已停止。")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
