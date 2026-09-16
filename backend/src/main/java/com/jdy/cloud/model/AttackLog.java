package com.jdy.cloud.model;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "attack_logs")
public class AttackLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 64)
    private String ip;

    @Column(name = "attack_type", length = 64)
    private String attackType;

    @Column(length = 500)
    private String path;

    @Column(length = 2000)
    private String payload;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @Column(length = 10)
    private String method;

    private Integer score;

    @Column(length = 32)
    private String action;

    @Column(name = "created_at")
    private LocalDateTime createdAt = LocalDateTime.now();
}
