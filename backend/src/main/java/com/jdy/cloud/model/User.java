package com.jdy.cloud.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

@Data
@Entity
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false, unique = true, length = 30)
    private String username;
    @Column(nullable = false, unique = true, length = 100)
    private String email;
    @Column(nullable = false)
    private String password;
    @Column(length = 20)
    private String role = "user";
    @Column(name = "is_official")
    private Boolean isOfficial = false;
    @Column(name = "user_status", length = 20)
    private String userStatus = "active";
    @Column(name = "verification_status", length = 20)
    private String verificationStatus = "unverified";
    @Column(name = "storage_used")
    private Long storageUsed = 0L;
    @Column(name = "storage_limit")
    private Long storageLimit = 314572800L;
    @Column(name = "upload_limit")
    // IronWall v1.28.3: 单文件上传上限默认 850MB（管理员无视）
    private Integer uploadLimit = 850;
    @Column(name = "user_code", length = 5, unique = true)
    private String userCode;

    @Column(name = "verification_badge", length = 50)
    private String verificationBadge;

    @Column(length = 500)
    private String avatar;
    @Column(name = "avatar_size")
    private Long avatarSize = 0L;
    @Column(name = "token_version")
    private Integer tokenVersion = 0;

    @Column(name = "login_attempts")
    private Integer loginAttempts = 0;
    @Column(name = "locked_until")
    private LocalDateTime lockedUntil;
    @Column(name = "created_at")
    private LocalDateTime createdAt = LocalDateTime.now();
    @Column(name = "updated_at")
    private LocalDateTime updatedAt = LocalDateTime.now();
    @PreUpdate
    protected void onUpdate() { updatedAt = LocalDateTime.now(); }
}
