package com.jdy.cloud.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * IronWall v1.41.0 / v1.42.0:
 * 路由表（逻辑模板 -> 真实路径模板）单一事实来源。
 *
 * 路由码周期轮换：
 * codeOf(logical, salt) 加盐哈希；salt 按「epoch 小时 / rotation-hours」周期滚动；
 * 校验侧同时接受：当期盐、上一期盐（灰度 grace-periods 期）与无盐旧码（旧客户端永久兼容）；
 * bootstrap 额外下发 code_map（无盐旧码 -> 当期码），前端把静态码翻译为当期码。
 *
 * 角色分级下发：
 * tierOf：admin/* -> 2（管理），files|shares/* -> 1（用户），其余 -> 0（匿名）。
 * routeMap(tier)/codeMap(tier) 仅包含该层级可见条目，管理面路径不再下发给匿名客户端。
 * 服务端 resolve/isCode 仍接受全表码——真正的权限边界由 Spring Security 角色鉴权保证，
 * 地图分级是「减少逆向面」的纵深防御，不替代授权。
 */
@Component
public final class ApiRouteTable {

    public static final int TIER_ANON = 0;
    public static final int TIER_USER = 1;
    public static final int TIER_ADMIN = 2;

    private static final Pattern PLACEHOLDER = Pattern.compile("\\{(\\d+)}");
    private static final String LEGACY_SALT = "";
    private static final int MAX_GRACE_PERIODS = 4;

    private static final String[][] ROUTES = buildRoutes();
    
        /**
         * 路由表由外部规则文件提供（{@code api.routes}）。
         *
         * <p>缺失时返回空表，{@link com.jdy.cloud.security.IronWallRules} 已在启动日志中列出缺失项。
         */
        private static String[][] buildRoutes() {
            List<List<String>> pairs = IronWallRules.pairs("api.routes");
            String[][] out = new String[pairs.size()][2];
            for (int i = 0; i < pairs.size(); i++) {
                out[i][0] = pairs.get(i).get(0);
                out[i][1] = pairs.get(i).get(1);
            }
            return out;
        };

    @Value("${app.security.api-crypto.route-code-rotation-hours:24}")
    private long rotationHours;

    @Value("${app.security.api-crypto.route-code-grace-periods:1}")
    private int gracePeriods;

    private final Map<String, Map<String, String>> saltedMaps = new ConcurrentHashMap<>();

    /** 逻辑模板 -> 无盐旧路由码（旧客户端永久兼容通道）。 */
    public static String codeOf(String logical) {
        return codeOf(logical, LEGACY_SALT);
    }

    /** 逻辑模板 -> 加盐路由码（64 位小写 hex）。 */
    public static String codeOf(String logical, String salt) {
        String input = (salt == null || salt.isEmpty()) ? logical : logical + ":" + salt;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("[IronWall] route code hash failed", e);
        }
    }

    /** 当前轮换盐：epoch 小时 / rotation-hours。 */
    public String currentSalt() {
        return saltForPeriod(0);
    }

    private String saltForPeriod(int back) {
        long hours = rotationHours > 0 ? rotationHours : 24;
        long period = System.currentTimeMillis() / 3600_000L / hours;
        return "r" + (period - back);
    }

    private Map<String, String> mapForSalt(String salt) {
        return saltedMaps.computeIfAbsent(salt == null ? LEGACY_SALT : salt, s -> {
            Map<String, String> m = new LinkedHashMap<>();
            for (String[] route : ROUTES) {
                m.put(codeOf(route[0], s), route[1]);
            }
            return Collections.unmodifiableMap(m);
        });
    }

    /** 校验侧接受的盐集合：当期 + 灰度历史期 + 无盐旧码。 */
    public Set<String> activeSalts() {
        int periods = Math.max(0, Math.min(gracePeriods, MAX_GRACE_PERIODS));
        Set<String> salts = new LinkedHashSet<>();
        for (int i = 0; i <= periods; i++) {
            salts.add(saltForPeriod(i));
        }
        salts.add(LEGACY_SALT);
        return salts;
    }

    /** 下发前端的加密路由地图：当期码 + 无盐旧码双键（老前端无感兼容）。 */
    public Map<String, String> routeMap(int tier) {
        Map<String, String> out = new LinkedHashMap<>();
        for (String[] route : ROUTES) {
            if (tierOf(route[0]) > tier) {
                continue;
            }
            out.put(codeOf(route[0], currentSalt()), route[1]);
            out.put(codeOf(route[0], LEGACY_SALT), route[1]);
        }
        return out;
    }

    public Map<String, String> routeMap() {
        return routeMap(TIER_ADMIN);
    }

    /** 无盐旧码 -> 当期码（前端把静态码翻译成当期码；轮换后旧码自动失效）。 */
    public Map<String, String> codeMap(int tier) {
        Map<String, String> out = new LinkedHashMap<>();
        for (String[] route : ROUTES) {
            if (tierOf(route[0]) > tier) {
                continue;
            }
            out.put(codeOf(route[0], LEGACY_SALT), codeOf(route[0], currentSalt()));
        }
        return out;
    }

    public Map<String, String> codeMap() {
        return codeMap(TIER_ADMIN);
    }

    /** 角色分级：admin/* -> 2；files|shares/* -> 1；其余（auth/site/version/feedback）-> 0。 */
    public static int tierOf(String logical) {
        if (logical == null) {
            return TIER_ANON;
        }
        if (logical.startsWith("admin/")) {
            return TIER_ADMIN;
        }
        // 密码挑战是公开分享页的匿名接口（SecurityConfig permitAll），归属匿名层
        if (logical.startsWith("shares/challenge/")) {
            return TIER_ANON;
        }
        if (logical.startsWith("files/") || logical.startsWith("shares/")) {
            return TIER_USER;
        }
        return TIER_ANON;
    }

    public boolean isCode(String segment) {
        if (segment == null) {
            return false;
        }
        for (String salt : activeSalts()) {
            if (mapForSalt(salt).containsKey(segment)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 由路由码 + 动态段还原真实路径。按 当期盐 -> 灰度历史盐 -> 无盐旧码 顺序尝试；
     * 占位符数量与动态段数量不一致、或含非法占位符时返回 null（调用方按拒绝处理）。
     */
    public String resolve(String code, List<String> segments) {
        if (code == null) {
            return null;
        }
        for (String salt : activeSalts()) {
            String template = mapForSalt(salt).get(code);
            if (template != null) {
                return resolveTemplate(template, segments);
            }
        }
        return null;
    }

    private String resolveTemplate(String template, List<String> segments) {
        List<String> segs = segments == null ? List.of() : segments;
        Matcher m = PLACEHOLDER.matcher(template);
        StringBuilder out = new StringBuilder();
        int maxIndex = -1;
        while (m.find()) {
            int idx;
            try {
                idx = Integer.parseInt(m.group(1));
            } catch (NumberFormatException e) {
                return null;
            }
            if (idx < 0 || idx >= segs.size() || segs.get(idx) == null || segs.get(idx).isBlank()) {
                return null;
            }
            maxIndex = Math.max(maxIndex, idx);
            m.appendReplacement(out, Matcher.quoteReplacement(segs.get(idx)));
        }
        m.appendTail(out);
        int placeholderCount = maxIndex + 1;
        if (placeholderCount != segs.size()) {
            return null;
        }
        return out.toString();
    }

    /** 供测试与同步校验使用：全部路由条目（logical, real）。 */
    public static List<String[]> entries() {
        List<String[]> copy = new ArrayList<>(ROUTES.length);
        for (String[] route : ROUTES) {
            copy.add(new String[]{route[0], route[1]});
        }
        return Collections.unmodifiableList(copy);
    }
}
