package com.jdy.cloud.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jdy.cloud.security.AttackGuardService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * IronWall v1.27.0: 版本发布与手动切换服务。
 * 新版本 jar 上传到 releases/ 目录后【不会】自动生效——首页与普通用户后台展示
 * 当前版本、待启用版本与更新日志，由用户在普通用户后台点击「立即更新」才执行切换：
 * 备份旧包 -> 替换 jdy-cloud.jar -> 调用 apply-update.sh 重启。
 */
@Slf4j
@Service
public class VersionReleaseService {

    private static final Pattern RELEASE_JAR = Pattern.compile("^jdy-cloud-v(\\d+)\\.(\\d+)\\.(\\d+)\\.jar$");
    private static final Pattern VERSION_ONLY = Pattern.compile("^\\d{1,4}(\\.\\d{1,4}){1,3}$");
    private static final long APPLY_COOLDOWN_MS = 5 * 60_000L;
    // IronWall v1.28.1: 同一账号切换冷却 30 分钟，防止普通用户高频触发重启滥用
    private static final long USER_APPLY_COOLDOWN_MS = 30 * 60_000L;

    private final ObjectMapper objectMapper;
    private final Path releasesDir;
    private final Path applyScript;
    private final boolean switchEnabled;
    private final AtomicBoolean applying = new AtomicBoolean(false);
    private volatile long lastApplyAt = 0L;
    private final Map<Long, Long> lastApplyByUser = new ConcurrentHashMap<>();

    public VersionReleaseService(ObjectMapper objectMapper,
                                 @Value("${app.version.releases-dir:./releases}") String releasesDir,
                                 @Value("${app.version.apply-script:./apply-update.sh}") String applyScript,
                                 @Value("${app.version.switch-enabled:true}") boolean switchEnabled) {
        this.objectMapper = objectMapper;
        this.releasesDir = Paths.get(releasesDir).toAbsolutePath().normalize();
        this.applyScript = Paths.get(applyScript).toAbsolutePath().normalize();
        this.switchEnabled = switchEnabled;
    }

    public Map<String, Object> info() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("current_version", currentVersion());
        out.put("changelog", changelog());
        return out;
    }

    public String currentVersion() {
        return AttackGuardService.ENGINE_VERSION;
    }

    /** 扫描 releases/jdy-cloud-vX.Y.Z.jar，按版本号倒序。 */
    public List<Map<String, Object>> stagedReleases() {
        List<String[]> found = new ArrayList<>();
        if (Files.isDirectory(releasesDir)) {
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(releasesDir, "jdy-cloud-v*.jar")) {
                for (Path p : stream) {
                    Matcher m = RELEASE_JAR.matcher(p.getFileName().toString());
                    if (m.matches()) {
                        found.add(new String[]{m.group(1) + "." + m.group(2) + "." + m.group(3), p.getFileName().toString()});
                    }
                }
            } catch (Exception e) {
                log.warn("[IronWall] releases scan failed: {}", e.getMessage());
            }
        }
        found.sort((a, b) -> compareVersion(b[0], a[0]));
        List<Map<String, Object>> out = new ArrayList<>();
        for (String[] f : found) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("version", "v" + f[0]);
            item.put("jar_file", f[1]);
            out.add(item);
        }
        return out;
    }

    /** 读取 releases/changelog.json（数组：version/date/title/details[]），缺失时返回空列表。 */
    public List<Map<String, Object>> changelog() {
        Path p = releasesDir.resolve("changelog.json");
        try {
            if (Files.isRegularFile(p)) {
                List<Map<String, Object>> list = objectMapper.readValue(Files.readAllBytes(p), new TypeReference<>() {});
                return list == null ? new ArrayList<>() : list;
            }
        } catch (Exception e) {
            log.warn("[IronWall] changelog read failed: {}", e.getMessage());
        }
        return new ArrayList<>();
    }

    public ApplyResult apply(String version) {
        return apply(version, null);
    }

    /** IronWall v1.28.1: 记录发起更新的用户并按账号限频（管理员与普通用户同一冷却规则）。 */
    public ApplyResult apply(String version, Long userId) {
        if (!switchEnabled) {
            return new ApplyResult(false, "更新开关未启用，请联系管理员。");
        }
        if (applying.get()) {
            return new ApplyResult(false, "正在切换版本中，请稍候。");
        }
        String v = version == null ? "" : version.trim();
        v = stripV(v);
        if (!VERSION_ONLY.matcher(v).matches()) {
            return new ApplyResult(false, "版本号格式不正确。");
        }
        if (compareVersion(v, stripV(currentVersion())) <= 0) {
            return new ApplyResult(false, "目标版本不高于当前运行版本。");
        }
        Path jar = releasesDir.resolve("jdy-cloud-v" + v + ".jar");
        if (!Files.isRegularFile(jar)) {
            return new ApplyResult(false, "未找到待启用版本文件 jdy-cloud-v" + v + ".jar，请先将新版本上传到 releases/ 目录。");
        }
        if (!Files.isRegularFile(applyScript)) {
            return new ApplyResult(false, "服务器缺少切换脚本 " + applyScript + "，请按部署文档创建。");
        }
        long now = System.currentTimeMillis();
        if (now - lastApplyAt < APPLY_COOLDOWN_MS) {
            return new ApplyResult(false, "切换操作过于频繁，请 " + (APPLY_COOLDOWN_MS / 60_000L) + " 分钟后再试。");
        }
        if (userId != null) {
            Long lastUser = lastApplyByUser.get(userId);
            if (lastUser != null && now - lastUser < USER_APPLY_COOLDOWN_MS) {
                return new ApplyResult(false, "同一账号切换操作过于频繁，请 " + (USER_APPLY_COOLDOWN_MS / 60_000L) + " 分钟后再试。");
            }
            lastApplyByUser.put(userId, now);
        }
        lastApplyAt = now;
        applying.set(true);
        final String target = "v" + v;
        log.warn("[IronWall] version switch requested: user={} {} -> {}", userId, currentVersion(), target);
        Thread worker = new Thread(() -> {
            try {
                ProcessBuilder pb = new ProcessBuilder("bash", applyScript.toString(), target);
                pb.redirectErrorStream(true);
                Process process = pb.start();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        log.info("[IronWall] apply-update: {}", line);
                    }
                }
                int code = process.waitFor();
                log.info("[IronWall] apply-update exited: {}", code);
            } catch (Exception e) {
                log.error("[IronWall] apply-update failed: {}", e.getMessage());
            } finally {
                applying.set(false);
            }
        }, "ironwall-version-switch");
        worker.setDaemon(true);
        worker.start();
        return new ApplyResult(true, "更新已触发，正在切换到 " + target + "，约 10-20 秒后生效，请稍后刷新页面。");
    }

    private int compareVersion(String a, String b) {
        String[] pa = a.split("\\.");
        String[] pb = b.split("\\.");
        for (int i = 0; i < Math.max(pa.length, pb.length); i++) {
            int x = i < pa.length ? parseIntSafe(pa[i]) : 0;
            int y = i < pb.length ? parseIntSafe(pb[i]) : 0;
            if (x != y) {
                return Integer.compare(x, y);
            }
        }
        return 0;
    }

    private int parseIntSafe(String s) {
        try {
            return Integer.parseInt(s);
        } catch (Exception e) {
            return 0;
        }
    }

    private String stripV(String version) {
        return version != null && version.startsWith("v") ? version.substring(1) : version;
    }

    public static class ApplyResult {
        public final boolean ok;
        public final String message;
        ApplyResult(boolean ok, String message) {
            this.ok = ok;
            this.message = message;
        }
    }
}
