package com.jdy.cloud.repository;

import com.jdy.cloud.model.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    Page<AuditLog> findAllByOrderByCreatedAtDesc(Pageable pageable);

    Page<AuditLog> findByActionOrderByCreatedAtDesc(String action, Pageable pageable);

    Page<AuditLog> findByUserIdOrderByCreatedAtDesc(Long userId, Pageable pageable);

    @Query("SELECT a FROM AuditLog a WHERE " +
           "(:action IS NULL OR a.action = :action) AND " +
           "(:userId IS NULL OR a.userId = :userId) AND " +
           "(:keyword IS NULL OR a.targetName LIKE %:keyword% OR a.detail LIKE %:keyword%) " +
           "ORDER BY a.createdAt DESC")
    Page<AuditLog> searchLogs(@Param("action") String action,
                              @Param("userId") Long userId,
                              @Param("keyword") String keyword,
                              Pageable pageable);

    @Query("SELECT a.action, COUNT(a) FROM AuditLog a GROUP BY a.action")
    List<Object[]> countByAction();

    long countByCreatedAtAfter(LocalDateTime after);
}