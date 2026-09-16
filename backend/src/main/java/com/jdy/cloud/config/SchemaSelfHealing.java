package com.jdy.cloud.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

/**
 * IronWall v1.10: 数据库结构自愈。
 *
 * 线上连续多轮头像上传 500 的根因之一：users 表缺少 avatar 列（实体已有该字段，
 * init.sql 中的 ALTER 被注释从未执行），导致保存头像 URL 时 SQL 直接报错。
 * 本组件在应用启动完成后自动补齐缺失列，权限不足或语句失败仅告警，绝不影响启动。
 */
@Slf4j
@Component
@Order(0)
public class SchemaSelfHealing implements ApplicationRunner {

    private final JdbcTemplate jdbcTemplate;

    public SchemaSelfHealing(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            ensureColumn("users", "avatar", "ALTER TABLE users ADD COLUMN avatar VARCHAR(500) DEFAULT NULL COMMENT 'avatar-url'");
            ensureColumn("users", "user_code", "ALTER TABLE users ADD COLUMN user_code VARCHAR(5) DEFAULT NULL COMMENT 'user-code'");
            ensureColumn("users", "verification_badge", "ALTER TABLE users ADD COLUMN verification_badge VARCHAR(50) DEFAULT NULL COMMENT 'verification-badge'");
            ensureColumn("users", "avatar_size", "ALTER TABLE users ADD COLUMN avatar_size BIGINT DEFAULT 0 COMMENT 'avatar-size'");
            ensureColumn("users", "token_version", "ALTER TABLE users ADD COLUMN token_version INT NOT NULL DEFAULT 0 COMMENT 'token-version'");
            backfillUserCodes();
            normalizeVerificationStatus();
            normalizeUploadLimits();
            ensurePasswordColumnWidened();
            log.info("[IronWall] SchemaSelfHealing check finished");
        } catch (Exception e) {
            log.warn("[IronWall] SchemaSelfHealing skipped: {}", e.getMessage());
        }
    }

    /**
     * IronWall v1.28.2: 用户认证状态数据自愈。
     * 管理员账号（role=admin）认证状态为空时自动标记为已认证并授予「官方认证」徽章，
     * 普通用户认证状态为空时归入待认证，保证管理后台「用户认证」列表不遗漏任何账号。
     */
    private void normalizeVerificationStatus() {
        try {
            int admin = jdbcTemplate.update(
                "UPDATE users SET verification_status='verified', verification_badge='官方认证' " +
                "WHERE LOWER(role)='admin' AND (verification_status IS NULL OR verification_status='')");
            int normal = jdbcTemplate.update(
                "UPDATE users SET verification_status='unverified' " +
                "WHERE (verification_status IS NULL OR verification_status='')");
            if (admin > 0 || normal > 0) {
                log.info("[IronWall] SchemaSelfHealing: verification status normalized admin={} normal={}", admin, normal);
            }
        } catch (Exception e) {
            log.warn("[IronWall] SchemaSelfHealing: verification normalization failed: {}", e.getMessage());
        }
    }

    /**
     * IronWall v1.28.3: 单文件上传上限统一为 850MB（历史账号旧值 100 一并抬升）；
     * 普通用户仍受 storage_limit（默认 300MB）配额约束，管理员无视限制。
     */
    private void normalizeUploadLimits() {
        try {
            int up = jdbcTemplate.update(
                "UPDATE users SET upload_limit=850 WHERE upload_limit IS NULL OR upload_limit < 850");
            if (up > 0) {
                log.info("[IronWall] SchemaSelfHealing: upload_limit normalized rows={}", up);
            }
        } catch (Exception e) {
            log.warn("[IronWall] SchemaSelfHealing: upload_limit normalization failed: {}", e.getMessage());
        }
    }

    private void ensureColumn(String table, String column, String ddl) {
        try {
            Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM information_schema.COLUMNS " +
                "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?",
                Integer.class, table, column);
            if (count != null && count > 0) {
                return;
            }
            log.warn("[IronWall] SchemaSelfHealing: missing column {}.{} -> applying DDL", table, column);
            jdbcTemplate.execute(ddl);
            log.info("[IronWall] SchemaSelfHealing: column {}.{} added", table, column);
        } catch (Exception e) {
            log.warn("[IronWall] SchemaSelfHealing: ensure column {}.{} failed: {}", table, column, e.getMessage());
        }
    }

    /**
     * IronWall v1.47.5 / v1.47.6: 靓号补全与固定性自愈。
     * 规则（幂等，重复启动结果一致）：
     * 1) 已有 user_code 的账号一律不动（靓号生成一次、永久固定）；
     * 2) 99999 为管理员专属固定靓号：普通用户若历史撞号则让位重发，最小 id 管理员固定 99999；
     * 3) 其余缺失靓号的账号从随机池补号，随机池永不生成 99999。
     */
    private void backfillUserCodes() {
        try {
            List<String> existing = jdbcTemplate.queryForList(
                    "SELECT user_code FROM users WHERE user_code IS NOT NULL AND user_code <> ''", String.class);
            Set<String> used = new HashSet<>(existing == null ? List.of() : existing);
            used.add("99999");
            Random rnd = new Random();
            int assigned = 0;

            // 1) 普通用户历史占用 99999 → 让位（先让位，避免唯一约束冲突）
            List<Long> holders = jdbcTemplate.queryForList(
                    "SELECT id FROM users WHERE user_code = '99999' AND LOWER(COALESCE(role, '')) <> 'admin'", Long.class);
            if (holders != null) {
                for (Long holderId : holders) {
                    String code = nextFreeCode(used, rnd, holderId);
                    if (code == null) {
                        continue;
                    }
                    if (jdbcTemplate.update("UPDATE users SET user_code=? WHERE id=?", code, holderId) > 0) {
                        assigned++;
                    }
                }
            }

            // 2) 管理员固定 99999（最小 id 管理员优先；其余管理员走随机补号）
            Long adminHolder = jdbcTemplate.queryForList(
                    "SELECT id FROM users WHERE user_code = '99999' AND LOWER(COALESCE(role, '')) = 'admin' ORDER BY id LIMIT 1",
                    Long.class).stream().findFirst().orElse(null);
            if (adminHolder == null) {
                List<Long> admins = jdbcTemplate.queryForList(
                        "SELECT id FROM users WHERE LOWER(COALESCE(role, '')) = 'admin' ORDER BY id", Long.class);
                if (admins != null && !admins.isEmpty()) {
                    Long adminId = admins.get(0);
                    if (jdbcTemplate.update("UPDATE users SET user_code='99999' WHERE id=?", adminId) > 0) {
                        used.add("99999");
                        assigned++;
                    }
                }
            }

            // 3) 其余缺失靓号账号补随机 5 位靓号（99999 已保留，永不命中）
            List<Long> ids = jdbcTemplate.queryForList(
                    "SELECT id FROM users WHERE user_code IS NULL OR user_code = ''", Long.class);
            if (ids != null) {
                for (Long id : ids) {
                    String code = nextFreeCode(used, rnd, id);
                    if (code == null) {
                        continue;
                    }
                    if (jdbcTemplate.update("UPDATE users SET user_code=? WHERE id=?", code, id) > 0) {
                        assigned++;
                    }
                }
            }

            if (assigned > 0) {
                log.info("[IronWall] SchemaSelfHealing: user_code assigned/backfilled for {} users (admin fixed 99999)", assigned);
            }
        } catch (Exception e) {
            log.warn("[IronWall] SchemaSelfHealing: user_code backfill failed: {}", e.getMessage());
        }
    }

    /** 从随机池生成不与现有账号冲突的 5 位靓号（99999 已保留在 used 中，永不命中）。 */
    private String nextFreeCode(Set<String> used, Random rnd, Long userId) {
        for (int attempt = 0; attempt < 1000; attempt++) {
            String candidate = String.format("%05d", rnd.nextInt(100000));
            if (!used.contains(candidate)) {
                used.add(candidate);
                return candidate;
            }
        }
        log.warn("[IronWall] SchemaSelfHealing: user_code space exhausted for userId={}", userId);
        return null;
    }

    /**
     * IronWall v1.28.9: shares.password 由 VARCHAR(10) 加宽到 VARCHAR(128)，
     * 支撑分享密码加盐哈希存储（sha256$ + 64 位十六进制）。
     */
    private void ensurePasswordColumnWidened() {
        try {
            Integer maxLen = jdbcTemplate.queryForObject(
                "SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS " +
                "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'shares' AND COLUMN_NAME = 'password'",
                Integer.class);
            if (maxLen != null && maxLen >= 128) {
                return;
            }
            log.warn("[IronWall] SchemaSelfHealing: shares.password length {} -> 128, applying DDL", maxLen);
            jdbcTemplate.execute("ALTER TABLE shares MODIFY password VARCHAR(128) DEFAULT NULL COMMENT 'share-password-hash'");
            log.info("[IronWall] SchemaSelfHealing: shares.password widened to 128");
        } catch (Exception e) {
            log.warn("[IronWall] SchemaSelfHealing: widen shares.password failed: {}", e.getMessage());
        }
    }
}
