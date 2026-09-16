package com.jdy.cloud.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ChangePasswordRequest {
    // IronWall v1.9: 同时接受 old_password/oldPassword（防前端新旧打包参数漂移）
    @NotBlank(message = "原密码不能为空")
    @JsonAlias("oldPassword")
    private String oldPassword;

    @NotBlank(message = "新密码不能为空")
    @Size(min = 6, max = 50, message = "密码长度需在6-50字符之间")
    @JsonAlias("newPassword")
    private String newPassword;
}