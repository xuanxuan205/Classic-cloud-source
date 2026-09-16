package com.jdy.cloud.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * IronWall v1.14: storage counter self-healing.
 *
 * Historical bug: permanently deleting an ACTIVE file removed the DB row and the physical
 * file but never decremented users.storage_used, leaving phantom usage on the account
 * even after everything was cleared. v1.13 blocked the code path; this component
 * repairs the residual DATA at every startup:
 * storage_used = SUM(active files) + current avatar accounting (avatar_size).
 * No manual SQL is required. Any failure only warns and never blocks startup.
 */
@Slf4j
@Component
@Order(Ordered.LOWEST_PRECEDENCE)
public class StorageReconciler implements ApplicationRunner {

    private final JdbcTemplate jdbcTemplate;

    public StorageReconciler(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            int healed = repairStorageCounters();
            if (healed > 0) {
                log.warn("[IronWall] StorageReconciler healed {} drifted storage counters", healed);
            } else {
                log.info("[IronWall] StorageReconciler check finished: all storage counters consistent");
            }
        } catch (Exception e) {
            log.warn("[IronWall] StorageReconciler skipped: {}", e.getMessage());
        }
    }

    int repairStorageCounters() {
        List<Long> driftedUserIds = findDriftedUserIds();
        int healed = 0;
        for (Long userId : driftedUserIds) {
            try {
                long expected = expectedUsage(userId);
                int updated = jdbcTemplate.update(
                        "UPDATE users SET storage_used = ? WHERE id = ? AND COALESCE(storage_used, 0) <> ?",
                        expected, userId, expected);
                if (updated > 0) {
                    healed++;
                    log.warn("[IronWall] StorageReconciler reset storage_used for user {} to {}", userId, expected);
                }
            } catch (Exception e) {
                log.warn("[IronWall] StorageReconciler repair failed for user {}: {}", userId, e.getMessage());
            }
        }
        return healed;
    }

    private List<Long> findDriftedUserIds() {
        // Full check includes the avatar ledger; degrade to files-only when avatar_size column is missing.
        String withAvatar = "SELECT u.id FROM users u WHERE COALESCE(u.storage_used, 0) <> "
                + "COALESCE((SELECT SUM(f.file_size) FROM files f WHERE f.user_id = u.id AND f.status = 1), 0) "
                + "+ COALESCE(u.avatar_size, 0)";
        try {
            return jdbcTemplate.queryForList(withAvatar, Long.class);
        } catch (Exception columnMissing) {
            log.warn("[IronWall] StorageReconciler avatar_size column unavailable, falling back to files-only check: {}",
                    columnMissing.getMessage());
            String filesOnly = "SELECT u.id FROM users u WHERE COALESCE(u.storage_used, 0) <> "
                    + "COALESCE((SELECT SUM(f.file_size) FROM files f WHERE f.user_id = u.id AND f.status = 1), 0)";
            return jdbcTemplate.queryForList(filesOnly, Long.class);
        }
    }

    private long expectedUsage(Long userId) {
        Long fileTotal = jdbcTemplate.queryForObject(
                "SELECT COALESCE(SUM(file_size), 0) FROM files WHERE user_id = ? AND status = 1",
                Long.class, userId);
        long avatar = 0L;
        try {
            Long avatarSize = jdbcTemplate.queryForObject(
                    "SELECT COALESCE(avatar_size, 0) FROM users WHERE id = ?",
                    Long.class, userId);
            if (avatarSize != null) {
                avatar = avatarSize;
            }
        } catch (Exception columnMissing) {
            // avatar_size column missing: avatars are not accounted, treat as 0
        }
        return (fileTotal == null ? 0L : fileTotal) + avatar;
    }
}
