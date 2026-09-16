package com.jdy.cloud.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IronWall v1.28.8 七层蜜罐防线记分服务。
 *
 * 每层内容不同、难度递加：
 * L1 路径蜜罐：仿真敏感路径，触网即暴露扫描意图；
 * L2 假凭据与蜜标：假管理员登录 + 蜜标令牌，提交即暴露；
 * L3 深度仿真后台：多步假控制台（用户/文件接口），步步取证；
 * L4 假数据拖延：假备份/假导出慢速滴水响应，消耗攻击者资源；
 * L5 蜜标回放裁决：蜜标令牌被回放，由 AttackAlertFilter 立即 4441 快速封禁；
 * L6 对象存储仿真：假 S3/OSS 桶清单与假 SDK 凭证，深入即触发黑洞陷阱；
 * L7 运维网关仿真：假跳板机/SSH 网关，最高危定向渗透，触碰直接重罚。
 *
 * 本服务只负责分层记分与层级推进记录，不进行任何反向攻击。
 */
@Slf4j
@Service
public class HoneypotLayerService {

    public static final int L1_PATH = 1;
    public static final int L2_CREDENTIALS = 2;
    public static final int L3_CONSOLE = 3;
    public static final int L4_DATA = 4;
    public static final int L5_CANARY = 5;
    public static final int L6_OBJECT_STORAGE = 6;
    public static final int L7_OPS_GATEWAY = 7;

    private final AttackGuardService attackGuardService;
    private final Map<String, HoneypotState> states = new ConcurrentHashMap<>();
    private final Map<Integer, Long> layerTouches = new ConcurrentHashMap<>();

    public HoneypotLayerService(AttackGuardService attackGuardService) {
        this.attackGuardService = attackGuardService;
    }

    public static final class HoneypotState {
        public int deepestLayer;
        public int touches;
        public long lastTouchAt;
    }

    /**
     * 记录一次蜜罐触网：写入攻击流水并推进该 IP 的层级状态。
     *
     * @return 该 IP 当前推进到的最深层级
     */
    /**
     * IronWall v1.20 银行级加权：触网一层即警告、二层即高危、三层直接封禁、
     * 四层/五层按严重级别处置。分层难度拉满，让扫描器在 L1 就被识别并警告。
     */
    public int touch(int layer, String ip, String path, String userAgent, String method) {
        if (ip == null || path == null) return 0;
        String payload = "七层蜜罐·第" + layer + "层: " + path;
        try {
            int weight = Math.max(1, Math.min(layer, 7)) * 5;
            attackGuardService.recordWeighted(ip, AttackGuardService.TYPE_HONEYPOT, payload,
                    path, userAgent, method, false, weight);
        } catch (Exception e) {
            log.error("[IronWall] honeypot layer record failed: {}", e.getMessage());
        }
        layerTouches.merge(layer, 1L, Long::sum);
        HoneypotState state = states.computeIfAbsent(ip, k -> new HoneypotState());
        synchronized (state) {
            state.deepestLayer = Math.max(state.deepestLayer, layer);
            state.touches++;
            state.lastTouchAt = System.currentTimeMillis();
        }
        log.warn("[IronWall] honeypot layer touched: ip={} layer={} path={} touches={}",
                ip, layer, path, state.touches);
        return state.deepestLayer;
    }

    /** 各层触网累计计数快照（供管理端安全面板展示 L1~L5）。 */
    public Map<Integer, Long> layerCounts() {
        return Map.copyOf(layerTouches);
    }

    public HoneypotState stateOf(String ip) {
        return states.getOrDefault(ip, new HoneypotState());
    }

    /**
     * 清理 24 小时未活动的蜜罐状态，防止内存无限增长（由管理端统计接口调用）。
     */
    public int prune(long maxAgeMillis) {
        long now = System.currentTimeMillis();
        int removed = 0;
        for (Map.Entry<String, HoneypotState> entry : states.entrySet()) {
            if (now - entry.getValue().lastTouchAt > maxAgeMillis && states.remove(entry.getKey()) != null) {
                removed++;
            }
        }
        return removed;
    }
}
