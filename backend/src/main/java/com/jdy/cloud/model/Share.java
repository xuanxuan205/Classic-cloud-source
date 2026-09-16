package com.jdy.cloud.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

@Data
@Entity
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
@Table(name = "shares")
public class Share {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "share_type")
    private Integer shareType = 1;

    @Column(name = "file_id")
    private Long fileId;

    @Column(name = "folder_id")
    private Long folderId;

    @Column(name = "code", unique = true, length = 20)
    private String shareCode;

    @Column(length = 128)
    private String password;

    @Column(name = "download_limit")
    private Integer downloadLimit = -1;

    @Column(name = "download_count")
    private Integer downloadCount = 0;

    @Column(length = 500)
    private String description;

    @Column(length = 200)
    private String contact;

    @Column(name = "sharer_name", length = 100)
    private String sharerName;

    @Column
    private Integer status = 1;

    @Column(name = "expire_time")
    private LocalDateTime expireTime;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @Column(name = "is_deleted", nullable = false)
    private Boolean isDeleted = false;

    @Column(name = "created_at")
    private LocalDateTime createdAt = LocalDateTime.now();
}
