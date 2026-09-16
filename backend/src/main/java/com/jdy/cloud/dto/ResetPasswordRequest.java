package com.jdy.cloud.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ResetPasswordRequest {
    @NotBlank(message = "邮箱不能为空")
    @Email(message = "邮箱格式不正确")
    private String email;

    @NotBlank(message = "验证码不能为空")
    private String code;

    // IronWall v1.9: 同时接受 new_password/newPassword
    @NotBlank(message = "新密码不能为空")
    @Size(min = 6, max = 50, message = "密码长度需在6-50字符之间")
    @JsonAlias("newPassword")
    private String newPassword;
}