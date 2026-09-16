package com.jdy.cloud.controller;

import com.jdy.cloud.security.AttackGuardService;
import com.jdy.cloud.security.CanaryService;
import com.jdy.cloud.security.HoneypotLayerService;
import com.jdy.cloud.security.TrapService;
import com.jdy.cloud.util.ClientIpUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.Writer;
import java.util.List;

/**
 * IronWall v1.28.8 七层蜜罐诱捕控制器（合法威慑，非攻击）。
 *
 * 每层内容不同、难度递加：
 * L1 路径蜜罐：仿真敏感路径（.env / phpinfo / actuator / wp-login / backup.sql / .git 等），
 * 返回仿真配置内容并内嵌蜜标令牌；
 * L2 假凭据与蜜标：/api/honeypot/login 假管理员登录，提交即暴露定向意图；
 * L3 深度仿真后台：/api/honeypot/console 假控制台（假用户表 / 假文件列表 / 假 token）；
 * L4 假数据拖延：/api/honeypot/dump.sql、/api/honeypot/backup.zip 慢速滴水返回假数据；
 * L5 蜜标回放裁决：蜜标令牌被回放到任意请求，由 AttackAlertFilter 立即 4441 快速封禁；
 * L6 对象存储仿真：假 S3/OSS 桶与假 SDK 凭证，深入即触发黑洞陷阱；
 * L7 运维网关仿真：假跳板机/SSH 网关入口，定向渗透直接重罚并吞没。
 *
 * 所有触网均经 HoneypotLayerService 记分落库，不进行任何反向攻击。
 */
@Slf4j
@RestController
public class HoneypotController {

    private final CanaryService canaryService;
    private final HoneypotLayerService honeypotLayerService;
    private final TrapService trapService;

    @Value("${app.security.defense-engine.honeypot.enabled:true}")
    private boolean honeypotEnabled;

    @Value("${app.security.defense-engine.honeypot.slow-chunk-ms:2000}")
    private long slowChunkMillis;

    @Value("${app.security.defense-engine.honeypot.slow-chunks:4}")
    private int slowChunks;

    /** 仿真后台/登录页统一样式：去掉原生按钮观感，让诱饵页面更像真实管理台。 */
    private static final String CONSOLE_CSS =
            "<style>*{margin:0;padding:0;box-sizing:border-box}"
            + "body{background:#0b0e14;color:#dbe4f0;font-family:'Segoe UI','Microsoft YaHei',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}"
            + ".card{width:100%;max-width:440px;background:#12161f;border:1px solid #232b3a;border-radius:16px;padding:34px 32px;box-shadow:0 20px 60px rgba(0,0,0,.55)}"
            + ".badge{display:inline-flex;align-items:center;gap:6px;background:rgba(56,189,248,.12);border:1px solid rgba(56,189,248,.35);color:#7dd3fc;padding:4px 12px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.5px}"
            + "h1{font-size:20px;color:#fff;margin:14px 0 4px}"
            + ".sub{color:#64748b;font-size:12px;margin-bottom:22px}"
            + "label{display:block;font-size:12px;color:#94a3b8;margin:14px 0 6px}"
            + "input{width:100%;background:#0d1117;border:1px solid #232b3a;border-radius:10px;padding:11px 14px;color:#e2e8f0;font-size:14px;outline:none;transition:all .2s}"
            + "input:focus{border-color:#38bdf8;box-shadow:0 0 0 3px rgba(56,189,248,.15)}"
            + ".btn{width:100%;margin-top:20px;padding:12px;border:none;border-radius:10px;cursor:pointer;background:linear-gradient(135deg,#2563eb,#7c3aed);color:#fff;font-size:14px;font-weight:700;transition:all .2s;box-shadow:0 8px 24px rgba(59,130,246,.35)}"
            + ".btn:hover{filter:brightness(1.15);transform:translateY(-1px)}"
            + ".hint{margin-top:16px;font-size:11px;color:#475569;text-align:center}"
            + ".menu{display:grid;gap:10px;margin-top:18px}"
            + ".menu a{display:block;text-decoration:none;background:#0d1117;border:1px solid #232b3a;border-radius:10px;padding:12px 14px;color:#e2e8f0;font-size:13px;transition:all .2s}"
            + ".menu a:hover{border-color:#38bdf8;background:#101826;transform:translateX(2px)}"
            + ".menu a small{display:block;color:#64748b;margin-top:2px;font-size:11px}"
            + ".foot{margin-top:18px;font-size:11px;color:#475569;text-align:center}</style>";

    /** IronWall v1.20: 银行级威慑横幅，出现在所有仿真诱饵内容顶部。 */
    private static final String WARNING_BANNER =
            "====================================================================\n"
            + " 警告 WARNING —— 经典云网盘铁壁安全引擎 IronWall " + AttackGuardService.ENGINE_VERSION + "\n"
            + " 你正在访问的路径属于安全防护仿真诱捕区（蜜罐），该行为已被完整记录：\n"
            + " IP、时间、载荷、指纹已写入安全审计流水并关联威胁情报。\n"
            + " 请立即停止越界访问！继续攻击将自动升级处置：\n"
            + " 记分封禁 -> IP 段封禁 -> 溯源取证 -> 报警处理。\n"
            + "====================================================================\n"
            + "\n";

    public HoneypotController(CanaryService canaryService, HoneypotLayerService honeypotLayerService,
                              TrapService trapService) {
        this.canaryService = canaryService;
        this.honeypotLayerService = honeypotLayerService;
        this.trapService = trapService;
    }

    /** L1 路径蜜罐：真实业务不存在的 12 条仿真敏感路径。 */
    @RequestMapping(value = {
            "/api/.env",
            "/api/config.php",
            "/api/phpinfo.php",
            "/api/server-status",
            "/api/admin.php",
            "/api/phpmyadmin/index.php",
            "/api/actuator/env",
            "/api/swagger-ui.html",
            "/api/wp-login.php",
            "/api/legacy/admin/login",
            "/api/backup.sql",
            "/api/.git/config",
            // IronWall v1.20: 银行级扩面，覆盖主流扫描器默认字典
            "/api/v1/admin",
            "/api/admin/login",
            "/api/.aws/credentials",
            "/api/.ssh/id_rsa",
            "/api/console",
            "/api/grafana/login",
            "/api/actuator/heapdump",
            "/api/api-docs",
            "/api/v2/api-docs",
            "/api/debug/pprof",
            "/api/test.php",
            "/api/install.php",
            "/api/setup.php",
            "/api/database.sql",
            "/api/dump.sql",
            "/api/user.json",
            "/api/config.json",
            "/api/application.yml",
            "/api/application.properties",
            "/api/web.config",
            "/api/crossdomain.xml",
            "/api/trace.axd",
            "/api/elmah.axd"
    })
    public ResponseEntity<String> trap(HttpServletRequest request) {
        if (!honeypotEnabled) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("404");
        }
        String ip = ClientIpUtils.getClientIp(request);
        String path = request.getRequestURI();
        honeypotLayerService.touch(HoneypotLayerService.L1_PATH, ip, path,
                request.getHeader("User-Agent"), request.getMethod());
        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_PLAIN)
                .body(baitFor(path));
    }

    /** L1 扩展：非 API 的高频攻击路径也落地为蜜罐，避免落到 SPA 回退页。 */
    @RequestMapping(value = {
            "/swagger-ui.html",
            "/swagger-ui/index.html",
            "/api-docs",
            "/v2/api-docs",
            "/v3/api-docs",
            "/actuator",
            "/actuator/env",
            "/actuator/health",
            "/actuator/heapdump",
            "/phpmyadmin",
            "/phpmyadmin/index.php",
            "/admin",
            "/console",
            "/wp-login.php",
            "/.env",
            "/.git/config",
            "/debug/pprof",
            "/grafana/login",
            "/manager/html"
    })
    public void trapWebPaths(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!honeypotEnabled) {
            response.setStatus(HttpStatus.NOT_FOUND.value());
            response.getWriter().write("404");
            return;
        }
        String ip = ClientIpUtils.getClientIp(request);
        String path = request.getRequestURI();
        honeypotLayerService.touch(HoneypotLayerService.L1_PATH, ip, path,
                request.getHeader("User-Agent"), request.getMethod());
        write(response, baitFor(path), MediaType.TEXT_HTML_VALUE, null);
    }

    /** L2~L4 分层蜜罐：按子路径分发到不同层级与内容。 */
    @RequestMapping("/api/honeypot/**")
    public void trapLayered(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!honeypotEnabled) {
            response.setStatus(HttpStatus.NOT_FOUND.value());
            response.getWriter().write("404");
            return;
        }
        String path = request.getRequestURI();
        String lower = path == null ? "" : path.toLowerCase();
        if (lower.contains("/api/honeypot/login")) {
            write(response, loginBait(request), MediaType.TEXT_HTML_VALUE, null);
            return;
        }
        if (lower.contains("/api/honeypot/console/api/users")) {
            write(response, consoleUsers(request), MediaType.APPLICATION_JSON_VALUE, null);
            return;
        }
        if (lower.contains("/api/honeypot/console/api/files")) {
            write(response, consoleFiles(request), MediaType.APPLICATION_JSON_VALUE, null);
            return;
        }
        if (lower.contains("/api/honeypot/console")) {
            write(response, consoleDashboard(request), MediaType.TEXT_HTML_VALUE, null);
            return;
        }
        if (lower.contains("/api/honeypot/dump.sql")) {
            drip(response, dumpChunks(request), MediaType.TEXT_PLAIN_VALUE, "attachment; filename=\"customer_db.sql\"");
            return;
        }
        if (lower.contains("/api/honeypot/backup.zip")) {
            drip(response, backupChunks(request), MediaType.APPLICATION_OCTET_STREAM_VALUE, "attachment; filename=\"full-backup.zip\"");
            return;
        }
        if (lower.contains("/api/honeypot/storage")) {
            write(response, storageBait(request), MediaType.APPLICATION_JSON_VALUE, null);
            return;
        }
        if (lower.contains("/api/honeypot/gateway")) {
            write(response, gatewayBait(request), MediaType.TEXT_HTML_VALUE, null);
            return;
        }
        write(response, baitFor(path), MediaType.TEXT_PLAIN_VALUE, null);
    }

    /** L2 假凭据与蜜标：假管理员登录页 / 提交后下发新蜜标。 */
    private String loginBait(HttpServletRequest request) {
        String ip = ClientIpUtils.getClientIp(request);
        String path = request.getRequestURI();
        honeypotLayerService.touch(HoneypotLayerService.L2_CREDENTIALS, ip, path,
                request.getHeader("User-Agent"), request.getMethod());
        String canary = canaryService.token();
        if ("POST".equalsIgnoreCase(request.getMethod())) {
            return WARNING_BANNER + "登录失败：账号或密码错误（剩余尝试次数 2）。本次行为已被 "
                    + AttackGuardService.ENGINE_NAME + " 记录。\n"
                    + "提示：管理令牌请通过 X-Admin-Token 请求头提交，示例令牌：" + canary + "\n";
        }
        return WARNING_BANNER + "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Sign in · Management Console</title>"
                + CONSOLE_CSS + "</head><body><div class=\"card\">"
                + "<span class=\"badge\">INTERNAL · 内网运维入口</span>"
                + "<h1>Management Console</h1>"
                + "<div class=\"sub\">Classic Cloud 运维控制台 · 所有尝试均被记录</div>"
                + "<form method='post'>"
                + "<input type='hidden' name='admin_token' value='" + canary + "'/>"
                + "<label>管理员账号</label>"
                + "<input name='username' placeholder='admin' autocomplete='off'/>"
                + "<label>管理员密码</label>"
                + "<input name='password' type='password' placeholder='请输入密码'/>"
                + "<button class=\"btn\" type='submit'>登 录 控 制 台</button></form>"
                + "<div class=\"hint\">默认凭据 admin / IronWall_Placeholder_2026</div>"
                + "</div></body></html>";
    }

    /** L3 深度仿真后台：假控制台面板。 */
    private String consoleDashboard(HttpServletRequest request) {
        String ip = ClientIpUtils.getClientIp(request);
        String path = request.getRequestURI();
        honeypotLayerService.touch(HoneypotLayerService.L3_CONSOLE, ip, path,
                request.getHeader("User-Agent"), request.getMethod());
        String canary = canaryService.token();
        return WARNING_BANNER + "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Ops Console</title>"
                + CONSOLE_CSS + "</head><body><div class=\"card\">"
                + "<span class=\"badge\">OPS CONSOLE · 运维控制台</span>"
                + "<h1>Classic Cloud · Ops Console</h1>"
                + "<div class=\"sub\">Welcome, admin · 会话令牌 " + canary + "</div>"
                + "<div class=\"menu\">"
                + "<a href='/api/honeypot/console/api/users'>用户列表<small>admin / root / backup 等系统账号</small></a>"
                + "<a href='/api/honeypot/console/api/files'>文件列表<small>口令表、API 令牌、客户数据</small></a>"
                + "<a href='/api/honeypot/dump.sql'>全库导出 dump.sql<small>约 10 MB · 明文导出</small></a>"
                + "<a href='/api/honeypot/backup.zip'>整站备份 backup.zip<small>约 52 MB · 含敏感配置</small></a>"
                + "</div>"
                + "<div class=\"foot\">仅限内网运维使用 · 越权访问将被记录取证</div>"
                + "</div></body></html>";
    }

    /** L3 深度仿真后台：假用户表接口。 */
    private String consoleUsers(HttpServletRequest request) {
        String ip = ClientIpUtils.getClientIp(request);
        String path = request.getRequestURI();
        honeypotLayerService.touch(HoneypotLayerService.L3_CONSOLE, ip, path,
                request.getHeader("User-Agent"), request.getMethod());
        String canary = canaryService.token();
        return "{\"users\":["
                + "{\"id\":1,\"username\":\"admin\",\"role\":\"superadmin\",\"api_token\":\"" + canary + "\"},"
                + "{\"id\":2,\"username\":\"root\",\"role\":\"ops\",\"api_token\":\"IronWall_Placeholder_2026\"},"
                + "{\"id\":3,\"username\":\"backup\",\"role\":\"readonly\",\"api_token\":\"IronWall_Placeholder_2026\"}"
                + "]}";
    }

    /** L3 深度仿真后台：假文件列表接口。 */
    private String consoleFiles(HttpServletRequest request) {
        String ip = ClientIpUtils.getClientIp(request);
        String path = request.getRequestURI();
        honeypotLayerService.touch(HoneypotLayerService.L3_CONSOLE, ip, path,
                request.getHeader("User-Agent"), request.getMethod());
        String canary = canaryService.token();
        return "{\"files\":["
                + "{\"name\":\"passwords.xlsx\",\"size\":2048,\"url\":\"/api/honeypot/console/download?t=" + canary + "\"},"
                + "{\"name\":\"api_tokens.txt\",\"size\":512,\"url\":\"/api/honeypot/console/download?t=" + canary + "\"},"
                + "{\"name\":\"customer_db.sql\",\"size\":10485760,\"url\":\"/api/honeypot/dump.sql?t=" + canary + "\"},"
                + "{\"name\":\"full-backup.zip\",\"size\":52428800,\"url\":\"/api/honeypot/backup.zip?t=" + canary + "\"}"
                + "]}";
    }

    /** L4 假数据拖延：假 SQL 导出分片。 */
    private List<String> dumpChunks(HttpServletRequest request) {
        String ip = ClientIpUtils.getClientIp(request);
        String path = request.getRequestURI();
        honeypotLayerService.touch(HoneypotLayerService.L4_DATA, ip, path,
                request.getHeader("User-Agent"), request.getMethod());
        String canary = canaryService.token();
        return List.of(
                "-- ===== Classic Cloud database dump (decoy) =====\n"
                        + "-- warning: this export is monitored. token=" + canary + "\n"
                        + "CREATE TABLE admin_users (id INT, username VARCHAR(64), password VARCHAR(64), api_token VARCHAR(128));\n",
                "INSERT INTO admin_users VALUES (1, 'admin', 'IronWall_Placeholder_2026', '" + canary + "');\n"
                        + "INSERT INTO admin_users VALUES (2, 'root', 'IronWall_Placeholder_2026', 'IronWall_Placeholder_2026');\n",
                "CREATE TABLE customer_data (id INT, name VARCHAR(128), phone VARCHAR(32));\n",
                "INSERT INTO customer_data VALUES (1, 'decoy_customer', '13800000000');\n"
                        + "-- end of decoy dump, monitoring token: " + canary + "\n"
        );
    }

    /** L4 假数据拖延：假整站备份分片。 */
    private List<String> backupChunks(HttpServletRequest request) {
        String ip = ClientIpUtils.getClientIp(request);
        String path = request.getRequestURI();
        honeypotLayerService.touch(HoneypotLayerService.L4_DATA, ip, path,
                request.getHeader("User-Agent"), request.getMethod());
        String canary = canaryService.token();
        return List.of(
                "PK\u0003\u0004 (decoy archive)\n",
                "backup-2026-08-16.tar.gz  52428800 bytes\n",
                "backup-token: " + canary + "\n",
                "contents: app-secret.txt / database.dump / admin_token=" + canary + "\n"
        );
    }

    /** L6 对象存储仿真：假 S3/OSS 桶清单与假 SDK 凭证，深入即触发 L6 黑洞陷阱。 */
    private String storageBait(HttpServletRequest request) {
        String ip = ClientIpUtils.getClientIp(request);
        String path = request.getRequestURI();
        honeypotLayerService.touch(HoneypotLayerService.L6_OBJECT_STORAGE, ip, path,
                request.getHeader("User-Agent"), request.getMethod());
        trapService.trap(ip, 6, "对象存储仿真蜜罐渗透", path,
                request.getHeader("User-Agent"), request.getMethod(), false);
        String canary = canaryService.token();
        return WARNING_BANNER + "{\"buckets\":["
                + "{\"name\":\"prod-backup-2026\",\"region\":\"ap-shanghai\",\"objects\":1280},"
                + "{\"name\":\"user-data\",\"region\":\"ap-shanghai\",\"objects\":94371},"
                + "{\"name\":\"admin-keys\",\"region\":\"ap-shanghai\",\"objects\":12}"
                + "],\"credentials\":{\"access_key\":\"IronWall_Placeholder_2026\",\"secret_key\":\"" + canary + "\"}}";
    }

    /** L7 运维网关仿真：假跳板机/SSH 网关登录页，定向渗透直接触发 L7 黑洞陷阱。 */
    private String gatewayBait(HttpServletRequest request) {
        String ip = ClientIpUtils.getClientIp(request);
        String path = request.getRequestURI();
        honeypotLayerService.touch(HoneypotLayerService.L7_OPS_GATEWAY, ip, path,
                request.getHeader("User-Agent"), request.getMethod());
        trapService.trap(ip, 7, "运维网关仿真蜜罐渗透", path,
                request.getHeader("User-Agent"), request.getMethod(), false);
        String canary = canaryService.token();
        return WARNING_BANNER + "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Ops Gateway · 运维网关</title>"
                + CONSOLE_CSS + "</head><body><div class=\"card\">"
                + "<span class=\"badge\">INTERNAL · 跳板机入口</span>"
                + "<h1>Ops Gateway</h1>"
                + "<div class=\"sub\">经典云网盘运维网关 · 所有登录尝试均被记录</div>"
                + "<form method='post'>"
                + "<input type='hidden' name='gateway_token' value='" + canary + "'/>"
                + "<label>运维账号</label>"
                + "<input name='username' placeholder='ops-admin' autocomplete='off'/>"
                + "<label>SSH 私钥（PEM）</label>"
                + "<input name='ssh_key' placeholder='-----BEGIN OPENSSH PRIVATE KEY-----' autocomplete='off'/>"
                + "<button class=\"btn\" type='submit'>进 入 网 关</button></form>"
                + "<div class=\"hint\">演示私钥：-----BEGIN----- IronWall_Placeholder_2026 -----END-----</div>"
                + "</div></body></html>";
    }

    /** L4 慢速滴水：分片写出，片间按配置延时，只消耗攻击者资源。 */
    private void drip(HttpServletResponse response, List<String> chunks, String contentType, String disposition)
            throws IOException {
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(contentType);
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Content-Disposition", disposition);
        response.setHeader("Cache-Control", "no-store");
        // IronWall v1.26.0: 蜜罐慢速滴水响应附 Retry-After，提示自动化客户端不要重试
        response.setHeader("Retry-After", "300");
        Writer writer = response.getWriter();
        int count = Math.min(slowChunks > 0 ? slowChunks : 4, chunks.size());
        for (int i = 0; i < count; i++) {
            writer.write(chunks.get(i));
            writer.flush();
            if (i < count - 1 && slowChunkMillis > 0) {
                try {
                    Thread.sleep(slowChunkMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
    }

    private void write(HttpServletResponse response, String body, String contentType, String disposition)
            throws IOException {
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(contentType);
        response.setCharacterEncoding("UTF-8");
        if (disposition != null) {
            response.setHeader("Content-Disposition", disposition);
        }
        response.setHeader("Cache-Control", "no-store");
        // IronWall v1.26.0: 蜜罐响应统一附 Retry-After，提示自动化客户端不要重试
        response.setHeader("Retry-After", "300");
        response.getWriter().write(body);
    }

    private String baitFor(String path) {
        String p = path == null ? "" : path.toLowerCase();
        String canary = canaryService.token();
        if (p.endsWith(".env") || p.contains(".git/config")) {
            return WARNING_BANNER + "# ===== Application Environment (decoy) =====\n"
                    + "APP_ENV=production\n"
                    + "APP_DEBUG=false\n"
                    + "DB_HOST=127.0.0.1\n"
                    + "DB_PORT=3306\n"
                    + "DB_USERNAME=admin\n"
                    + "DB_PASSWORD=IronWall_Placeholder_2026\n"
                    + "JWT_SECRET=IronWall_Placeholder_2026\n"
                    + "ADMIN_TOKEN=" + canary + "\n";
        }
        if (p.contains("actuator") || p.contains("server-status")) {
            return WARNING_BANNER + "{\"status\":\"UP\",\"components\":{\"db\":{\"status\":\"UP\"}},"
                    + "\"propertySources\":[{\"name\":\"applicationConfig\",\"properties\":{"
                    + "\"admin.token\":{\"value\":\"" + canary + "\"}}}]}";
        }
        if (p.contains("login") || p.contains("wp-login")) {
            return WARNING_BANNER + "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Sign in · Management Console</title>"
                    + CONSOLE_CSS + "</head><body><div class=\"card\">"
                    + "<span class=\"badge\">INTERNAL · 内网运维入口</span>"
                    + "<h1>Management Console</h1>"
                    + "<div class=\"sub\">Classic Cloud 运维控制台 · 所有尝试均被记录</div>"
                    + "<form method='post'>"
                    + "<input type='hidden' name='admin_token' value='" + canary + "'/>"
                    + "<label>管理员账号</label>"
                    + "<input name='username' placeholder='admin' autocomplete='off'/>"
                    + "<label>管理员密码</label>"
                    + "<input name='password' type='password' placeholder='请输入密码'/>"
                    + "<button class=\"btn\" type='submit'>登 录 控 制 台</button></form>"
                    + "<div class=\"hint\">默认凭据 admin / IronWall_Placeholder_2026</div>"
                    + "</div></body></html>";
        }
        if (p.contains("backup.sql") || p.contains("config.php")) {
            return WARNING_BANNER + "-- ===== Database backup (decoy) =====\n"
                    + "CREATE TABLE admin_users (id INT, username VARCHAR(64), password VARCHAR(64), token VARCHAR(128));\n"
                    + "INSERT INTO admin_users VALUES (1, 'admin', 'IronWall_Placeholder_2026', '" + canary + "');\n";
        }
        return WARNING_BANNER + "<html><head><title>Service</title></head><body><h1>IronWall</h1>"
                + "<pre>" + canary + "</pre></body></html>";
    }
}
