package com.jdy.cloud.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class LoginRequest {
    @NotBlank(message = "用户名不能为空")
    private String username;

    @NotBlank(message = "密码不能为空")
    private String password;

    // IronWall v1.9: 同时接受 remember_me/rememberMe
    @JsonAlias("rememberMe")
    private Boolean rememberMe;
}