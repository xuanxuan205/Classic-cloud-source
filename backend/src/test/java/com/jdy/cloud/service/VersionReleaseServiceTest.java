package com.jdy.cloud.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * IronWall v1.27.0: 版本发布服务的扫描、排序、更新日志读取与切换前置校验。
 */
class VersionReleaseServiceTest {

    @TempDir
    Path tmp;

    private VersionReleaseService svc(boolean enabled) {
        return new VersionReleaseService(
                new ObjectMapper(),
                tmp.resolve("releases").toString(),
                tmp.resolve("apply-update.sh").toString(),
                enabled);
    }

    @Test
    void stagedReleases_sortsDescending_andFiltersInvalidNames() throws Exception {
        Path releases = tmp.resolve("releases");
        Files.createDirectories(releases);
        Files.write(releases.resolve("jdy-cloud-v1.26.2.jar"), new byte[]{1});
        Files.write(releases.resolve("jdy-cloud-v1.27.0.jar"), new byte[]{1});
        Files.write(releases.resolve("jdy-cloud-v2.0.1.jar"), new byte[]{1});
        Files.write(releases.resolve("jdy-cloud-evil.jar"), new byte[]{1});
        Files.write(releases.resolve("evil.jar"), new byte[]{1});

        List<Map<String, Object>> staged = svc(true).stagedReleases();
        assertEquals(3, staged.size());
        assertEquals("v2.0.1", staged.get(0).get("version"));
        assertEquals("v1.27.0", staged.get(1).get("version"));
        assertEquals("v1.26.2", staged.get(2).get("version"));
    }

    @Test
    void changelog_readsJson() throws Exception {
        Path releases = tmp.resolve("releases");
        Files.createDirectories(releases);
        Files.write(releases.resolve("changelog.json"),
                "[{\"version\":\"v1.27.0\",\"title\":\"t\",\"details\":[\"a\"]}]".getBytes());

        List<Map<String, Object>> log = svc(true).changelog();
        assertEquals(1, log.size());
        assertEquals("v1.27.0", log.get(0).get("version"));
    }

    @Test
    void info_reportsCurrentVersion_andNoUpdateByDefault() {
        Map<String, Object> info = svc(true).info();
        assertEquals("v1.48.0", info.get("current_version"));
        // IronWall v1.28.7: 远程更新接口已移除，info 不得再暴露待启用版本与更新开关
        assertFalse(info.containsKey("has_update"));
        assertFalse(info.containsKey("staged"));
        assertFalse(info.containsKey("apply_ready"));
    }

    @Test
    void apply_rejectsWhenDisabled() {
        VersionReleaseService.ApplyResult r = svc(false).apply("v9.9.9");
        assertFalse(r.ok);
        assertTrue(r.message.contains("更新开关未启用"));
    }

    @Test
    void apply_rejectsWhenNotHigherThanCurrent() {
        VersionReleaseService.ApplyResult r = svc(true).apply("v1.0.0");
        assertFalse(r.ok);
        assertTrue(r.message.contains("目标版本不高于当前运行版本"));
    }

    @Test
    void apply_rejectsWhenJarMissing() {
        VersionReleaseService.ApplyResult r = svc(true).apply("v9.9.9");
        assertFalse(r.ok);
        assertTrue(r.message.contains("未找到待启用版本文件"));
    }

    @Test
    void apply_rejectsWhenScriptMissing() throws Exception {
        Path releases = tmp.resolve("releases");
        Files.createDirectories(releases);
        Files.write(releases.resolve("jdy-cloud-v9.9.9.jar"), new byte[]{1});

        VersionReleaseService.ApplyResult r = svc(true).apply("v9.9.9");
        assertFalse(r.ok);
        assertTrue(r.message.contains("切换脚本"));
    }
}
