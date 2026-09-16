package com.jdy.cloud.repository;

import com.jdy.cloud.model.FileEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDateTime;
import java.util.List;

public interface FileRepository extends JpaRepository<FileEntity, Long> {
    Page<FileEntity> findByUserIdAndFolderIdAndStatus(Long userId, Long folderId, int status, Pageable pageable);
    Page<FileEntity> findByUserIdAndStatus(Long userId, int status, Pageable pageable);
    long countByUserIdAndStatus(Long userId, int status);

    @Query("SELECT COALESCE(SUM(f.fileSize), 0) FROM FileEntity f WHERE f.userId = :userId AND f.status = :status")
    long sumFileSizeByUserIdAndStatus(@Param("userId") Long userId, @Param("status") int status);

    // IronWall v1.47.3: 用户口径下载次数聚合（我的文件统计卡权威数据源）
    @Query("SELECT COALESCE(SUM(f.downloadCount), 0) FROM FileEntity f WHERE f.userId = :userId AND f.status = :status")
    long sumDownloadCountByUserIdAndStatus(@Param("userId") Long userId, @Param("status") int status);

    List<FileEntity> findByFolderIdAndStatus(Long folderId, int status);

    long countByCreatedAtAfter(LocalDateTime after);

    // IronWall v1.47.4: download stats exclude permanently deleted rows
    @Query("SELECT COALESCE(SUM(f.downloadCount), 0) FROM FileEntity f WHERE f.status <> -1")
    long sumDownloadCount();

    // IronWall v1.47.4: dashboard file count aligns with admin file list (excludes deleted)
    long countByStatusNot(int status);

    // IronWall v1.47.4: atomic file download counter (share downloads write here too)
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Transactional
    @Query("UPDATE FileEntity f SET f.downloadCount = COALESCE(f.downloadCount, 0) + 1 WHERE f.id = :fileId")
    int incrementDownloadCount(@Param("fileId") Long fileId);

    // IronWall v1.47.6: 管理端文件搜索（文件名 / 归属用户），保持排除已删除
    Page<FileEntity> findByOriginalNameContainingIgnoreCaseAndStatusNot(String originalName, int status, Pageable pageable);

    @Query("SELECT f FROM FileEntity f WHERE (f.status <> -1 AND LOWER(COALESCE(f.originalName, '')) LIKE LOWER(CONCAT('%', :kw, '%'))) OR (f.status <> -1 AND f.userId IN :userIds)")
    Page<FileEntity> searchByKeywordOrUserIds(@Param("kw") String kw, @Param("userIds") List<Long> userIds, Pageable pageable);

    // IronWall v1.28.0: 秒传去重（同 hash + 同大小 + 正常状态复用物理文件）
    java.util.Optional<FileEntity> findFirstByFileHashAndFileSizeAndStatusOrderByIdAsc(String fileHash, Long fileSize, int status);

    // IronWall v1.28.0: 物理文件引用计数（去重后彻底删除前校验，防止误删他人文件）
    long countByFilename(String filename);

    // IronWall v1.28.0: 回收站到期自动清理候选
    java.util.List<FileEntity> findByStatusAndUpdatedAtBefore(int status, java.time.LocalDateTime cutoff);

    // IronWall v1.47.0: 管理员列表排除已删除(-1)；遗留孤儿行清理候选
    Page<FileEntity> findByStatusNot(int status, Pageable pageable);
    java.util.List<FileEntity> findByStatus(int status);
}
