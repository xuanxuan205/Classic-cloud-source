package com.jdy.cloud.repository;

import com.jdy.cloud.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);

    boolean existsByUserCode(String userCode);
    Optional<User> findByUserCode(String userCode);
    Optional<User> findByUsernameOrEmail(String username, String email);

    // 管理员引导：判断库中是否已有管理员，用于决定是否需要创建首个管理员
    @Query("SELECT COUNT(u) FROM User u WHERE LOWER(COALESCE(u.role, '')) = LOWER(:role)")
    long countByRole(@Param("role") String role);

    // IronWall v1.47.4: dashboard active users + site-wide storage aggregates
    long countByUserStatus(String userStatus);

    @Query("SELECT COALESCE(SUM(u.storageUsed), 0) FROM User u")
    long sumStorageUsed();

    @Query("SELECT COALESCE(SUM(u.storageLimit), 0) FROM User u")
    long sumStorageLimit();

    // IronWall IW-02: Unified login lookup across username/email/userCode
    @Query("SELECT u FROM User u WHERE u.username = :loginId OR u.email = :loginId OR u.userCode = :loginId")
    Optional<User> findByLoginId(@Param("loginId") String loginId);

    // IronWall v1.47.6: 管理端全量关键词搜索（用户名/邮箱/靓号，大小写不敏感）
    @Query("SELECT u FROM User u WHERE LOWER(COALESCE(u.username, '')) LIKE LOWER(CONCAT('%', :kw, '%')) " +
           "OR LOWER(COALESCE(u.email, '')) LIKE LOWER(CONCAT('%', :kw, '%')) " +
           "OR LOWER(COALESCE(u.userCode, '')) LIKE LOWER(CONCAT('%', :kw, '%'))")
    Page<User> searchByKeyword(@Param("kw") String kw, Pageable pageable);

    @Query("SELECT u.id FROM User u WHERE LOWER(COALESCE(u.username, '')) LIKE LOWER(CONCAT('%', :kw, '%')) " +
           "OR LOWER(COALESCE(u.email, '')) LIKE LOWER(CONCAT('%', :kw, '%')) " +
           "OR LOWER(COALESCE(u.userCode, '')) LIKE LOWER(CONCAT('%', :kw, '%'))")
    List<Long> findIdsByKeyword(@Param("kw") String kw);

    // IronWall v1.10: atomic storage counter updates (no read-modify-write race, no parent-row entity save)
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE User u SET u.storageUsed = COALESCE(u.storageUsed, 0) + :delta WHERE u.id = :userId AND COALESCE(u.storageUsed, 0) + :delta >= 0")
    int incrementStorageUsed(@Param("userId") Long userId, @Param("delta") long delta);

    // IronWall v1.12: avatar metadata atomic update (avoids stale full-entity saves clobbering counters)
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE User u SET u.avatar = :avatarUrl, u.avatarSize = :avatarSize WHERE u.id = :userId")
    int updateAvatar(@Param("userId") Long userId, @Param("avatarUrl") String avatarUrl, @Param("avatarSize") long avatarSize);

    // IronWall v1.13: native fallbacks for environments where avatar_size column is missing
    // (SchemaSelfHealing may lack ALTER permission). Fallback chain: JPQL -> native with size -> URL-only.
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = "UPDATE users SET avatar = :avatarUrl, avatar_size = :avatarSize WHERE id = :userId", nativeQuery = true)
    int updateAvatarNative(@Param("userId") Long userId, @Param("avatarUrl") String avatarUrl, @Param("avatarSize") long avatarSize);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = "UPDATE users SET avatar = :avatarUrl WHERE id = :userId", nativeQuery = true)
    int updateAvatarUrlOnly(@Param("userId") Long userId, @Param("avatarUrl") String avatarUrl);

    // IronWall v1.10: quota-enforcing atomic increment, 0 rows means out of quota or user missing
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE User u SET u.storageUsed = COALESCE(u.storageUsed, 0) + :delta WHERE u.id = :userId AND COALESCE(u.storageUsed, 0) + :delta >= 0 AND COALESCE(u.storageUsed, 0) + :delta <= COALESCE(u.storageLimit, 0)")
    int incrementStorageUsedWithinLimit(@Param("userId") Long userId, @Param("delta") long delta);
}
