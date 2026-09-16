package com.jdy.cloud.repository;

import com.jdy.cloud.model.LoginHistory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LoginHistoryRepository extends JpaRepository<LoginHistory, Long> {
    Page<LoginHistory> findByUserIdOrderByTimeDesc(Long userId, Pageable pageable);

    Page<LoginHistory> findAllByOrderByTimeDesc(Pageable pageable);

    Page<LoginHistory> findByStatus(String status, Pageable pageable);
}
