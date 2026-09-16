package com.jdy.cloud.security;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * IronWall v1.25.1: 服务器前置护盾状态服务。
 *
 * 状态来源：服务器上 root cron 每分钟执行 update-ironwall-shield.sh，
 * 把 fail2ban / 防火墙 / SSH / MySQL / 开放端口等系统层防护状态写入
 * logs/server-shield-state.json（www 可读），后端只读该文件并向管理后台提供
 * /api/admin/security/server-shield 接口。后端以非 root 身份运行，不直接
 * 调用系统命令，权限边界与安全边界保持最小化。
 */
@Slf4j
@Service
public class ServerShieldService {

    @Value("${app.security.server-shield.enabled:true}")
    private boolean enabled;

    @Value("${app.security.server-shield.state-file:./logs/server-shield-state.json}")
    private String stateFile;

    private static final long CACHE_TTL_MS = 15_000L;
    private static final long STALE_THRESHOLD_MS = 5 * 60_000L;

    private final ObjectMapper objectMapper;
    private final AttackGuardService attackGuardService;

    private volatile Map<String, Object> cachedState;
    private volatile long cachedAt = 0L;

    public ServerShieldService(ObjectMapper objectMapper, AttackGuardService attackGuardService) {
        this.objectMapper = objectMapper;
        this.attackGuardService = attackGuardService;
    }

    public boolean isEnabled() {
        return enabled;
    }

    /** 读取缓存或重新加载状态文件（最多每 15 秒读盘一次）。 */
    private Map<String, Object> readState(boolean force) {
        long now = System.currentTimeMillis();
        if (!force && cachedState != null && (now - cachedAt) < CACHE_TTL_MS) {
            return cachedState;
        }
        Map<String, Object> parsed = loadFromDisk();
        cachedState = parsed;
        cachedAt = now;
        return parsed;
    }

    private Map<String, Object> loadFromDisk() {
        if (!enabled) {
            return null;
        }
        try {
            File file = new File(stateFile);
            if (!file.isFile() || !file.canRead()) {
                return null;
            }
            Map<String, Object> parsed = objectMapper.readValue(file, new TypeReference<Map<String, Object>>() {
            });
            return parsed == null ? new LinkedHashMap<>() : parsed;
        } catch (Exception e) {
            log.debug("server-shield state unreadable: {}", e.getMessage());
            return null;
        }
    }

    /** 管理后台接口数据：状态原文 + 五层护盾摘要 + 安装提示。 */
    public Map<String, Object> getShieldStatus(boolean force) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("engine", AttackGuardService.ENGINE_FULL_NAME);
        result.put("enabled", enabled);
        Map<String, Object> state = readState(force);
        result.put("installed", state != null);
        if (state == null) {
            result.put("stale", false);
            result.put("message", "未检测到服务器护盾状态文件：请在服务器执行 server-guard/install-server-shield.sh 安装每分钟采集任务");
            result.put("fail2ban", null);
            result.put("firewall", null);
            result.put("ssh", null);
            result.put("mysql", null);
            result.put("warnings", Collections.emptyList());
        } else {
            result.put("schema", state.get("schema"));
            result.put("generated_at", state.get("generated_at"));
            result.put("hostname", state.get("hostname"));
            result.put("stale", isStale(state));
            result.put("fail2ban", state.get("fail2ban"));
            result.put("firewall", state.get("firewall"));
            result.put("ssh", state.get("ssh"));
            result.put("mysql", state.get("mysql"));
            result.put("listening_public", state.get("listening_public"));
            result.put("hids", state.get("hids"));
            result.put("tamper_proof", state.get("tamper_proof"));
            result.put("backup", state.get("backup"));
            result.put("nginx_status", state.getOrDefault("nginx_status", Collections.emptyMap()));
            result.put("decoy_ports", state.getOrDefault("decoy_ports", Collections.emptyList()));
            result.put("portscan", state.getOrDefault("portscan", Collections.emptyMap()));
            result.put("warnings", state.getOrDefault("warnings", Collections.emptyList()));
        }
        result.put("layers", buildLayers(state));
        result.put("layer_status", overallLayerStatus(result));
        return result;
    }

    private boolean isStale(Map<String, Object> state) {
        Object at = state.get("generated_at");
        if (!(at instanceof String s) || s.isBlank()) {
            return true;
        }
        try {
            Instant instant = Instant.parse(s);
            return (System.currentTimeMillis() - instant.toEpochMilli()) > STALE_THRESHOLD_MS;
        } catch (Exception e) {
            return true;
        }
    }

    /** 五层护盾摘要：入口收敛 -> 铁壁引擎 -> 系统联动 -> 服务加固 -> 数据保全。 */
    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> buildLayers(Map<String, Object> state) {
        List<Map<String, Object>> layers = new ArrayList<>();

        Map<String, Object> fw = asMap(state == null ? null : state.get("firewall"));
        Map<String, Object> f2b = asMap(state == null ? null : state.get("fail2ban"));
        Map<String, Object> ssh = asMap(state == null ? null : state.get("ssh"));
        Map<String, Object> mysql = asMap(state == null ? null : state.get("mysql"));
        Map<String, Object> tamper = asMap(state == null ? null : state.get("tamper_proof"));
        Map<String, Object> backup = asMap(state == null ? null : state.get("backup"));

        boolean l1 = Boolean.TRUE.equals(fw.get("active"))
                && Boolean.TRUE.equals(fw.get("ports_ok"));
        layers.add(layer("L1 入口收敛", "防火墙仅放行 80/443（面板与 SSH 绑定白名单 IP）",
                state == null ? "off" : (l1 ? "ok" : "warn"),
                state == null ? "状态未采集" : (l1 ? "对外端口已收敛" : "存在未收敛端口或防火墙未启用")));

        boolean l2 = attackGuardService.isEnabled();
        layers.add(layer("L2 铁壁引擎", "nginx 反代 + IronWall Web 层攻击检测与封禁",
                l2 ? "ok" : "off", l2 ? "防护运行中" : "引擎已停用"));

        boolean l3 = Boolean.TRUE.equals(f2b.get("running")) && hasEnabledJail(f2b, "ironwall");
        layers.add(layer("L3 系统联动", "网站层封禁 -> fail2ban 全端口封禁联动桥",
                state == null ? "off" : (l3 ? "ok" : "warn"),
                state == null ? "状态未采集" : (l3 ? "联动桥运行中" : "fail2ban 或 ironwall 监狱未运行")));

        boolean l4 = Boolean.TRUE.equals(ssh.get("hardened")) && Boolean.TRUE.equals(mysql.get("local_only"));
        layers.add(layer("L4 服务加固", "SSH 密钥登录 + MySQL 仅内网监听",
                state == null ? "off" : (l4 ? "ok" : "warn"),
                state == null ? "状态未采集" : (l4 ? "核心服务已加固" : "SSH/MySQL 存在暴露面")));

        boolean l5 = Boolean.TRUE.equals(tamper.get("enabled")) || Boolean.TRUE.equals(backup.get("enabled"));
        layers.add(layer("L5 数据保全", "目录防篡改 + 数据库/文件自动备份",
                state == null ? "off" : (l5 ? "ok" : "warn"),
                state == null ? "状态未采集" : (l5 ? "保全措施已开启" : "建议开启防篡改与定时备份")));
        return layers;
    }

    private Map<String, Object> layer(String name, String desc, String status, String detail) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", name);
        m.put("desc", desc);
        m.put("status", status);
        m.put("detail", detail);
        return m;
    }

    private String overallLayerStatus(Map<String, Object> result) {
        Object layers = result.get("layers");
        if (!(layers instanceof List<?> list)) {
            return "off";
        }
        boolean anyOff = false;
        boolean anyWarn = false;
        for (Object o : list) {
            if (o instanceof Map<?, ?> m) {
                Object status = m.get("status");
                if ("off".equals(status)) anyOff = true;
                if ("warn".equals(status)) anyWarn = true;
            }
        }
        if (anyOff) return "off";
        if (anyWarn) return "warn";
        return "ok";
    }

    @SuppressWarnings("unchecked")
    private boolean hasEnabledJail(Map<String, Object> f2b, String name) {
        Object jails = f2b.get("jails");
        if (!(jails instanceof List<?> list)) {
            return false;
        }
        for (Object o : list) {
            if (o instanceof Map<?, ?> m
                    && name.equals(m.get("name"))
                    && Boolean.TRUE.equals(m.get("enabled"))) {
                return true;
            }
        }
        return false;
    }

    private Map<String, Object> asMap(Object value) {
        if (value instanceof Map<?, ?> m) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : m.entrySet()) {
                out.put(String.valueOf(e.getKey()), e.getValue());
            }
            return out;
        }
        return Collections.emptyMap();
    }
}
