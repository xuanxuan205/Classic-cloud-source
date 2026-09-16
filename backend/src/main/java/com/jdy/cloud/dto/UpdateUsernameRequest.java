package com.jdy.cloud.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UpdateUsernameRequest {
    @NotBlank(message = "用户名不能为空")
    @Size(min = 2, max = 30, message = "用户名长度需在2-30个字符之间")
    private String username;

    // IronWall v1.43.0: 改用户名需验证当前密码（敏感操作统一二次认证）
    @NotBlank(message = "密码不能为空")
    private String password;
}
