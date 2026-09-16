package com.jdy.cloud.security;

import java.util.Set;

/**
 * IronWall v1.17 蜜罐路径清单：这些路径在真实业务中不存在，
 * 只有扫描器/攻击者会触碰。命中即记录 + 返回仿真诱饵内容。
 */
public final class HoneypotPaths {

    public static final Set<String> DECOYS = Set.copyOf(IronWallRules.list("honeypot.paths"));

    private HoneypotPaths() {
    }

    public static boolean isHoneypot(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase();
        for (String decoy : DECOYS) {
            if (lower.equals(decoy)) return true;
        }
        return lower.startsWith("/api/honeypot/");
    }
}
