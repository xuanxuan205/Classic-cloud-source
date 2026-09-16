package com.jdy.cloud.repository;

import com.jdy.cloud.model.Folder;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface FolderRepository extends JpaRepository<Folder, Long> {
    List<Folder> findByUserIdAndParentIdAndStatus(Long userId, Long parentId, int status);
    List<Folder> findByParentIdAndStatus(Long parentId, int status);
    boolean existsByParentIdAndNameAndStatus(Long parentId, String name, int status);
}
