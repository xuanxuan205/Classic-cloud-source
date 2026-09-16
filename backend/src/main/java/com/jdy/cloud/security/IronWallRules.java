package com.jdy.cloud.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * IronWall 规则加载器。
 *
 * <p>检测规则由外部 JSON 提供，与代码解耦：
 * 环境变量 {@code IRONWALL_RULES_FILE}，或系统属性 {@code ironwall.rules.file}，
 * 默认 {@code ./config/ironwall-rules.json}。
 *
 * <p>随包提供 {@code ironwall-rules.sample.json} 作为默认规则集，部署者可复制一份
 * 并按需增补条目；未配置的条目对应检测族自动停用并在启动时告警，
 * 不会静默改变既有行为。
 *
 * <p>规则文件独立于 jar 分发，调整检测策略无需重新打包。
 */
@Slf4j
public final class IronWallRules {

    /** 默认规则文件路径。 */
    private static final String DEFAULT_PATH = "./config/ironwall-rules.json";

    /** 公开样例文件名：规则文件缺失时回退到它，保证新装的站点有一个可用基线。 */
    private static final String SAMPLE_NAME = "ironwall-rules.sample.json";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Map<String, Pattern> PATTERN_CACHE = new HashMap<>();

    /**
     * 规则缺失时返回的「永不匹配」占位符。
     *
     * <p>采用空对象模式而非返回 null，理由：调用方共 13 处直接使用
     * {@code PATTERN.matcher(x).find()} / {@code replaceAll(...)}，
     * 返回 null 会引入 NPE 或迫使每处都加判空。永不匹配的正则使
     * {@code find()} 恒为 false、{@code replaceAll} 原样返回，
     * 语义恰好等于「该检测族停用」，且归一化链路不会中断。
     */
    private static final Pattern NEVER = Pattern.compile("(?!)");

    private static volatile JsonNode root;
    private static volatile String source = DEFAULT_PATH;
    private static volatile Set<String> missing = Set.of();

    private IronWallRules() {
    }

    /** 解析规则文件路径：环境变量优先，其次系统属性，最后默认值。 */
    public static String resolvePath() {
        String env = System.getenv("IRONWALL_RULES_FILE");
        if (env != null && !env.isBlank()) {
            return env.trim();
        }
        return System.getProperty("ironwall.rules.file", DEFAULT_PATH);
    }

    /** 重新加载规则文件（供运维热更新或测试使用）。 */
    public static synchronized void load() {
        String path = resolvePath();
        source = path;
        synchronized (PATTERN_CACHE) {
            PATTERN_CACHE.clear();
        }
        File file = new File(path);
        if (!file.isFile()) {
            // 规则文件缺失时回退到同目录的默认规则集，
            // 保证新部署的站点开箱就有可用基线，而不是整块引擎哑火。
            File parent = file.getAbsoluteFile().getParentFile();
            File sample = parent == null ? null : new File(parent, SAMPLE_NAME);
            if (sample != null && sample.isFile()) {
                source = sample.getPath();
                log.warn("[IronWall] 规则文件不存在：{}，已回退到默认规则集：{}。"
                        + "如需自定义检测策略，可复制一份到 {} 并按需增补条目。",
                        path, source, path);
                file = sample;
            } else {
                root = MAPPER.createObjectNode();
                // 文件都没有 = 全部条目都缺。此处绝不能报「无缺失」，
                // 否则调用方（含测试准入判断）会误以为规则集是完整的。
                missing = Set.copyOf(REQUIRED_KEYS);
                log.warn("[IronWall] 规则文件不存在：{}，同目录也没有 {}。"
                        + "基于规则的检测族将全部停用（站点功能不受影响）。", path, SAMPLE_NAME);
                return;
            }
        }
        try {
            String text = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
            root = MAPPER.readTree(text);
            missing = collectMissing(root);
            if (missing.isEmpty()) {
                log.info("[IronWall] 规则文件已加载：{}", path);
            } else {
                log.warn("[IronWall] 规则文件已加载：{}，缺失 {} 项，相关检测族已停用：{}",
                        path, missing.size(), missing);
            }
        } catch (Exception e) {
            root = MAPPER.createObjectNode();
            missing = Set.copyOf(REQUIRED_KEYS);
            log.error("[IronWall] 规则文件解析失败：{}（{}）。检测族全部停用。", source, e.getMessage());
        }
    }

    /**
     * 内置的期望条目清单。
     * 缺失项在启动日志中一次性列出，便于按图索骥补全。
     */
    private static final List<String> REQUIRED_KEYS = List.of(
            "patterns.sqli",
            "patterns.sqliOperator",
            "patterns.sqliOperatorFamily",
            "patterns.sqliMysqlBuiltin",
            "patterns.sqliHex",
            "patterns.xss",
            "patterns.traversal",
            "patterns.cmd",
            "patterns.ssrf",
            "patterns.suspiciousPath",
            "patterns.crawlerUa",
            "patterns.toolUa",
            "patterns.highRiskPath",
            "patterns.uploadPath",
            "patterns.doubleWriteToken",
            "patterns.unicodeWhitespace",
            "patterns.sqlInlineComment",
            "patterns.usernameParam",
            "patterns.usernameJson",
            "patterns.jsonUnicodeEscape",
            "patterns.jsonStringEscape",
            "normalization.doubleWriteMap",
            "honeypot.paths",
            "honeypot.loginPath"
    );

    /*
     * 注意：本静态块必须位于所有静态字段（尤其 REQUIRED_KEYS）的**文本声明之后**。
     * Java 按文本顺序初始化静态字段，若提前到 REQUIRED_KEYS 之前，
     * load() 内的 collectMissing 会读到 null 并抛 NPE，导致规则被整体判为加载失败。
     */
    static {
        load();
    }

    private static Set<String> collectMissing(JsonNode tree) {
        Set<String> out = new LinkedHashSet<>();
        for (String key : REQUIRED_KEYS) {
            JsonNode cursor = tree;
            for (String seg : key.split("\\.")) {
                cursor = cursor == null ? null : cursor.get(seg);
            }
            if (cursor == null || cursor.isNull() || (cursor.isArray() && cursor.isEmpty())) {
                out.add(key);
            }
        }
        return Collections.unmodifiableSet(out);
    }

    /** 当前缺失的规则条目（供管理后台展示）。 */
    public static Set<String> missingKeys() {
        return missing;
    }

    /** 当前规则文件路径。 */
    public static String sourcePath() {
        return source;
    }

    private static JsonNode node(String dotted) {
        JsonNode cursor = root;
        if (cursor == null) {
            return null;
        }
        for (String seg : dotted.split("\\.")) {
            if (cursor == null) {
                return null;
            }
            cursor = cursor.get(seg);
        }
        return (cursor == null || cursor.isNull()) ? null : cursor;
    }

    /**
     * 条目是否存在且非空。
     *
     * <p>数组/对象按元素个数判断，不能走 {@code asText()}——对容器节点它恒返回空串，
     * 会把「有 79 条路由的数组」误判成不存在。
     */
    public static boolean has(String key) {
        JsonNode n = node(key);
        if (n == null) {
            return false;
        }
        if (n.isArray() || n.isObject()) {
            return n.size() > 0;
        }
        return !n.asText("").isBlank();
    }

    /** 取字符串条目，缺失返回 null。 */
    public static String str(String key) {
        JsonNode n = node(key);
        return (n == null || !n.isTextual()) ? null : n.asText();
    }

    /** 取正则条目；缺失返回永不匹配的占位符，调用方无需判空。 */
    public static Pattern p(String key) {
        JsonNode n = node(key);
        if (n == null || !n.isTextual() || n.asText().isBlank()) {
            return NEVER;
        }
        synchronized (PATTERN_CACHE) {
            return PATTERN_CACHE.computeIfAbsent(key, k -> Pattern.compile(n.asText()));
        }
    }

    /**
     * 取正则条目；缺失时回退到内置默认值。
     *
     * <p>专供「管线型」条目：它们解析的是本应用自身的数据（例如从请求体里取出 username），
     * 或对本应用自己的路由做分类，判断的并不是「什么算攻击」。
     *
     * <p>这类条目若按 {@link #p(String)} 退化为永不匹配，功能会**静默失效**
     * （登录蜜标直接不工作、高危路径不再加权），而不是安全地降级。因此内置一份默认值。
     *
     * <p>对抗型条目（sqli / xss / traversal …）一律不使用本重载：未配置即停用，
     * 以配置为准。
     */
    public static Pattern p(String key, String fallbackRegex) {
        JsonNode n = node(key);
        if (n != null && n.isTextual() && !n.asText().isBlank()) {
            return p(key);
        }
        synchronized (PATTERN_CACHE) {
            return PATTERN_CACHE.computeIfAbsent(key + "\u0000default",
                    k -> Pattern.compile(fallbackRegex));
        }
    }

    /** 取正则条目原文；缺失返回 null。用于需要区分「缺失」与「已配置」的场景。 */
    public static String patternSource(String key) {
        return str(key);
    }

    /** 取字符串条目；缺失或空白时回退到默认值。 */
    public static String str(String key, String fallback) {
        String v = str(key);
        return (v == null || v.isBlank()) ? fallback : v;
    }

    /** 取字符串数组条目，缺失返回空列表。 */
    public static List<String> list(String key) {
        JsonNode n = node(key);
        if (n == null || !n.isArray()) {
            return List.of();
        }
        List<String> out = new ArrayList<>(n.size());
        for (JsonNode e : n) {
            if (e.isTextual()) {
                out.add(e.asText());
            }
        }
        return Collections.unmodifiableList(out);
    }

    /** 取二元组数组条目（如路由表 [[逻辑名, 真实路径], ...]），缺失返回空列表。 */
    public static List<List<String>> pairs(String key) {
        JsonNode n = node(key);
        if (n == null || !n.isArray()) {
            return List.of();
        }
        List<List<String>> out = new ArrayList<>();
        for (JsonNode row : n) {
            if (row.isArray() && row.size() == 2 && row.get(0).isTextual() && row.get(1).isTextual()) {
                out.add(List.of(row.get(0).asText(), row.get(1).asText()));
            }
        }
        return out;
    }

    /** 取对象条目（如双写还原映射），缺失返回空表。 */
    public static Map<String, String> map(String key) {
        JsonNode n = node(key);
        if (n == null || !n.isObject()) {
            return Map.of();
        }
        Map<String, String> out = new LinkedHashMap<>();
        n.fields().forEachRemaining(e -> {
            if (e.getValue().isTextual()) {
                out.put(e.getKey(), e.getValue().asText());
            }
        });
        return Collections.unmodifiableMap(out);
    }

    /** 取整数条目，缺失返回默认值。 */
    public static int intOf(String key, int fallback) {
        JsonNode n = node(key);
        return (n == null || !n.isNumber()) ? fallback : n.asInt();
    }
}
