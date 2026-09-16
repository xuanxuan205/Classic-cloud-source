package com.jdy.cloud.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import lombok.Data;

@Data
public class UpdateUserRequest {
    private String username;
    private String email;
    private String role;

    // IronWall v1.9: 管理端字段同样双命名兼容
    @JsonAlias("userStatus")
    private String userStatus;

    @JsonAlias("storageLimit")
    private Long storageLimit;

    @JsonAlias("uploadLimit")
    private Integer uploadLimit;
}