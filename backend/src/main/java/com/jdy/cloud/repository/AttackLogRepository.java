package com.jdy.cloud.repository;

import com.jdy.cloud.model.AttackLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface AttackLogRepository extends JpaRepository<AttackLog, Long> {
    Page<AttackLog> findAllByOrderByCreatedAtDesc(Pageable pageable);

    @Query("SELECT COUNT(DISTINCT a.ip) FROM AttackLog a")
    long countDistinctIp();

    long countByCreatedAtAfter(java.time.LocalDateTime since);

    List<AttackLog> findTop100ByIpOrderByCreatedAtDesc(String ip);

    long countByAttackType(String attackType);

    /** IronWall v1.38.0: 封禁同步事件对账拉取。 */
    List<AttackLog> findTop50ByAttackTypeOrderByIdDesc(String attackType);
}
