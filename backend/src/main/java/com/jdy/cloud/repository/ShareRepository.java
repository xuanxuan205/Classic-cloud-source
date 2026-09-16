package com.jdy.cloud.repository;

import com.jdy.cloud.model.Share;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface ShareRepository extends JpaRepository<Share, Long> {
    Page<Share> findByUserIdOrderByCreatedAtDesc(Long userId, Pageable pageable);
    @Query("SELECT s FROM Share s WHERE LOWER(s.shareCode) = LOWER(:shareCode)")
    Optional<Share> findByShareCode(@Param("shareCode") String shareCode);

    /** IronWall v1.19: 永久删除文件前检查分享外键引用，避免 DataIntegrityViolationException 500 */
    boolean existsByFileId(Long fileId);

    /** IronWall v1.47.0: 文件永久删除时同步删除其单文件分享（文件夹分享依赖文件状态过滤）。 */
    long deleteByFileId(Long fileId);

    /**
     * IronWall v1.7: 下载次数原子判减一体（防 TOCTOU 竞态）。
     * 在数据库行锁内完成「判断未超限 + 计数加一」，并发请求只有一个能成功：
     * 返回 1 = 本次下载获准；返回 0 = 已超限或分享不存在。
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Transactional
    @Query("UPDATE Share s SET s.downloadCount = COALESCE(s.downloadCount, 0) + 1 " +
           "WHERE s.id = :shareId AND (COALESCE(s.downloadLimit, -1) < 0 OR COALESCE(s.downloadCount, 0) < s.downloadLimit)")
    int incrementDownloadCountIfAllowed(@Param("shareId") Long shareId);

    // IronWall v1.47.4: dashboard today-shares counter
    long countByCreatedAtAfter(LocalDateTime after);

    // IronWall v1.47.6: 管理端分享搜索（分享码 / 归属用户）
    Page<Share> findByShareCodeContainingIgnoreCase(String shareCode, Pageable pageable);

    Page<Share> findByShareCodeContainingIgnoreCaseOrUserIdIn(String shareCode, List<Long> userIds, Pageable pageable);
}
