package com.jdy.cloud.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * IronWall v1.28.8 七层假端口陷阱引擎（合法威慑，非攻击）。
 *
 * 每层自动生成多个随机假端口：攻击者一旦连接这些端口，服务器侧
 * decoy-port-manager.py 会吞没连接并联动 fail2ban 全端口封禁。
 * 本服务负责生成/轮换端口清单，为管理面板和封禁警示页提供展示，
 * 并提供「端口 -> 层级」查询能力。任何异常不影响真实业务。
 */
@Slf4j
@Service
public class DecoyPortTrapService {

    public static final int LAYERS = 7;
    private static final int PORTS_PER_LAYER = 3;
    private static final int PORT_MIN = 31000;
    private static final int PORT_MAX = 64999;

    /** 常见服务端口，假端口生成时永不占用。自定义端口（面板、改过的 SSH 等）用 IRONWALL_RESERVED_PORTS 追加。 */
    private static final Set<Integer> BASE_RESERVED = Set.of(
            21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
            3306, 33060, 8080, 8083, 888, 1723, 5000, 8000);

    private final Set<Integer> reserved;
    private final SecureRandom random = new SecureRandom();
    private volatile Map<Integer, List<Integer>> layerPorts;
    private volatile long rotatedAt = System.currentTimeMillis();

    public DecoyPortTrapService(@Value("${app.security.decoy.reserved-ports:}") String extraReserved) {
        this.reserved = parseReserved(extraReserved);
        this.layerPorts = generate();
    }

    /** 解析逗号分隔的额外保留端口；非法片段忽略，不抛异常。 */
    private static Set<Integer> parseReserved(String raw) {
        Set<Integer> out = new HashSet<>(BASE_RESERVED);
        if (raw == null || raw.isBlank()) {
            return out;
        }
        for (String part : raw.split(",")) {
            String token = part.trim();
            if (token.isEmpty()) {
                continue;
            }
            try {
                int port = Integer.parseInt(token);
                if (port > 0 && port <= 65535) {
                    out.add(port);
                }
            } catch (NumberFormatException e) {
                log.warn("[IronWall] decoy reserved port ignored: {}", token);
            }
        }
        return out;
    }

    /** 生成一套七层随机假端口，端口不重复且避开真实业务端口。 */
    public synchronized Map<Integer, List<Integer>> generate() {
        Map<Integer, List<Integer>> out = new LinkedHashMap<>();
        Set<Integer> used = new HashSet<>(reserved);
        for (int layer = 1; layer <= LAYERS; layer++) {
            List<Integer> ports = new ArrayList<>();
            int attempts = 0;
            while (ports.size() < PORTS_PER_LAYER && attempts < 10000) {
                attempts++;
                int port = PORT_MIN + random.nextInt(PORT_MAX - PORT_MIN + 1);
                if (used.add(port)) {
                    ports.add(port);
                }
            }
            out.put(layer, ports);
        }
        return out;
    }

    /** 管理员触发轮换：重新随机生成一层陷阱端口（只更换诱饵，不影响真实业务）。 */
    public synchronized List<Map<String, Object>> rotate() {
        layerPorts = generate();
        rotatedAt = System.currentTimeMillis();
        log.warn("[IronWall] decoy port traps rotated at {}", rotatedAt);
        return snapshot();
    }

    /** 判断某个端口属于第几层陷阱，非陷阱端口返回 -1。 */
    public int layerOf(int port) {
        for (Map.Entry<Integer, List<Integer>> e : layerPorts.entrySet()) {
            if (e.getValue().contains(port)) {
                return e.getKey();
            }
        }
        return -1;
    }

    /** 当前五层假端口清单（只读快照）。 */
    public Map<Integer, List<Integer>> ports() {
        return Collections.unmodifiableMap(layerPorts);
    }

    /** 管理层展示快照：层级、端口、服务伪装名与状态。 */
    public List<Map<String, Object>> snapshot() {
        List<Map<String, Object>> list = new ArrayList<>();
        for (Map.Entry<Integer, List<Integer>> e : layerPorts.entrySet()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("layer", e.getKey());
            m.put("ports", e.getValue());
            m.put("service", serviceName(e.getKey()));
            m.put("status", "active");
            list.add(m);
        }
        return list;
    }

    /** 伪装服务名：让诱饵端口更像真实运维服务，攻击者一旦连接即取证。 */
    public String serviceName(int layer) {
        switch (layer) {
            case 1: return "ops-http";
            case 2: return "redis-cache";
            case 3: return "mongo-admin";
            case 4: return "backup-rsync";
            case 5: return "monitor-agent";
            case 6: return "object-storage";
            case 7: return "gitlab-runner";
            default: return "decoy-service";
        }
    }

    public long rotatedAt() {
        return rotatedAt;
    }
}
