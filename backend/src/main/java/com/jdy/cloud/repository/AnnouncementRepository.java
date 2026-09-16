package com.jdy.cloud.repository;

import com.jdy.cloud.model.Announcement;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface AnnouncementRepository extends JpaRepository<Announcement, Long> {
    List<Announcement> findByStatusOrderByCreatedAtDesc(String status);

    List<Announcement> findByStatusInOrderByCreatedAtDesc(List<String> statuses);

    List<Announcement> findByStatus(String status);
}
