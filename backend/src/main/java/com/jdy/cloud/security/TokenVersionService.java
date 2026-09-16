package com.jdy.cloud.security;

import com.jdy.cloud.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IronWall v1.20: 令牌版本号服务（银行级会话吊销）。
 *
 * 改密 / 重置密码 / 管理员封禁时调用 {@link #bump(Long)}，用户 token_version +1：
 * 内存通道：立即生效，旧 JWT 在下一次请求即被 JwtAuthenticationFilter 拒绝（毫秒级吊销）；
 * 数据库通道：持久化版本号，重启后依旧吊销。
 *
 * 过滤器校验时优先读内存版本（无缓存延迟），内存无记录时回退数据库并短缓存（60 秒）。
 */
@Slf4j
@Service
public class TokenVersionService {

    private static final long DB_CACHE_TTL_MS = 60_000L;

    private final UserRepository userRepository;
    private final Map<Long, VersionEntry> memory = new ConcurrentHashMap<>();
    private final Map<Long, VersionEntry> dbCache = new ConcurrentHashMap<>();

    public TokenVersionService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    private static final class VersionEntry {
        final int version;
        final long expiresAt;
        VersionEntry(int version, long expiresAt) {
            this.version = version;
            this.expiresAt = expiresAt;
        }
    }

    /**
     * 递增指定用户的令牌版本号。数据库更新失败时至少保证内存生效（fail-secure），
     * 绝不让旧令牌在改密后继续可用。
     */
    public int bump(Long userId) {
        if (userId == null) return 0;
        int newVersion = 0;
        try {
            userRepository.findById(userId).ifPresent(u -> {
                int current = u.getTokenVersion() == null ? 0 : u.getTokenVersion();
                u.setTokenVersion(current + 1);
                userRepository.save(u);
                memory.put(userId, new VersionEntry(current + 1, System.currentTimeMillis() + 24 * 3600_000L));
            });
            VersionEntry entry = memory.get(userId);
            if (entry != null) newVersion = entry.version;
        } catch (Exception e) {
            log.error("[IronWall] token version bump failed for user={}: {}", userId, e.getMessage());
        }
        if (newVersion == 0) {
            // 内存兜底：即使数据库不可用，也把版本抬高，保证旧令牌立即失效
            VersionEntry entry = memory.compute(userId, (k, old) -> new VersionEntry(
                    (old != null ? old.version : 0) + 1, System.currentTimeMillis() + 24 * 3600_000L));
            newVersion = entry.version;
        }
        log.info("[IronWall] token version bumped: user={} version={}", userId, newVersion);
        return newVersion;
    }

    /** 判断 JWT 携带的版本号是否与用户当前版本一致。 */
    public boolean matches(Long userId, int tokenVersion) {
        if (userId == null) return false;
        VersionEntry mem = memory.get(userId);
        if (mem != null) {
            return tokenVersion >= mem.version;
        }
        VersionEntry cached = dbCache.get(userId);
        if (cached != null && cached.expiresAt > System.currentTimeMillis()) {
            return tokenVersion >= cached.version;
        }
        Integer current = null;
        try {
            current = userRepository.findById(userId)
                    .map(u -> u.getTokenVersion() == null ? 0 : u.getTokenVersion())
                    .orElse(null);
        } catch (Exception e) {
            log.error("[IronWall] token version db read failed, fail-open for user={}: {}", userId, e.getMessage());
            return true;
        }
        int currentVersion = current == null ? 0 : current;
        dbCache.put(userId, new VersionEntry(currentVersion, System.currentTimeMillis() + DB_CACHE_TTL_MS));
        return tokenVersion >= currentVersion;
    }

    public int current(Long userId) {
        if (userId == null) return 0;
        VersionEntry mem = memory.get(userId);
        if (mem != null) return mem.version;
        Integer current = currentFromDb(userId);
        return current == null ? 0 : current;
    }

    private Integer currentFromDb(Long userId) {
        try {
            Integer current = userRepository.findById(userId)
                    .map(u -> u.getTokenVersion() == null ? 0 : u.getTokenVersion())
                    .orElse(null);
            return current;
        } catch (Exception e) {
            log.error("[IronWall] token version db read failed, fail-open for user={}: {}", userId, e.getMessage());
            return null;
        }
    }
}
