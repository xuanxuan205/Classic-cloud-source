package com.jdy.cloud.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import lombok.Data;

@Data
public class CreateShareRequest {
    // IronWall v1.9: 分享创建全部多词字段双命名兼容（snake_case + camelCase）
    @JsonAlias("fileId")
    private Long fileId;

    @JsonAlias("folderId")
    private Long folderId;

    @JsonAlias("shareType")
    private int shareType = 1;

    private int days;

    @JsonAlias("expiresIn")
    private Integer expiresIn;

    @JsonAlias("expireDays")
    private Integer expireDays;

    private String password;
    private String description;
    private String contact;

    @JsonAlias("sharerName")
    private String sharerName;

    // IronWall v1.8: 同时接受 download_limit(snake_case) 与 downloadLimit(camelCase)，
    // 防止前端旧打包/直连请求使用驼峰键导致下载限次被静默忽略
    @JsonAlias("downloadLimit")
    private int downloadLimit;
}