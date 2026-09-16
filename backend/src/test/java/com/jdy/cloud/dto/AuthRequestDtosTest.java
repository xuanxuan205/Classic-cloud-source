package com.jdy.cloud.dto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IronWall v1.9: 认证/管理接口请求体双命名契约测试。
 * 后端全局 SNAKE_CASE，因此每个多词字段都必须同时接受 snake_case 与 camelCase，
 * 从根上杜绝新旧前端打包之间的参数漂移导致 UI 功能失效。
 */
class AuthRequestDtosTest {

    private final ObjectMapper mapper = new ObjectMapper()
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);

    @Test
    void changePassword_shouldAcceptBothConventions() throws Exception {
        ChangePasswordRequest snake = mapper.readValue(
                "{\"old_password\":\"a\",\"new_password\":\"b\"}", ChangePasswordRequest.class);
        assertEquals("a", snake.getOldPassword());
        assertEquals("b", snake.getNewPassword());

        ChangePasswordRequest camel = mapper.readValue(
                "{\"oldPassword\":\"c\",\"newPassword\":\"d\"}", ChangePasswordRequest.class);
        assertEquals("c", camel.getOldPassword());
        assertEquals("d", camel.getNewPassword());
    }

    @Test
    void resetPassword_shouldAcceptBothConventions() throws Exception {
        ResetPasswordRequest snake = mapper.readValue(
                "{\"email\":\"a@b.c\",\"code\":\"123456\",\"new_password\":\"x\"}", ResetPasswordRequest.class);
        assertEquals("x", snake.getNewPassword());

        ResetPasswordRequest camel = mapper.readValue(
                "{\"email\":\"a@b.c\",\"code\":\"123456\",\"newPassword\":\"y\"}", ResetPasswordRequest.class);
        assertEquals("y", camel.getNewPassword());
    }

    @Test
    void login_shouldAcceptRememberMeBothConventions() throws Exception {
        assertEquals(Boolean.TRUE, mapper.readValue("{\"username\":\"u\",\"password\":\"p\",\"remember_me\":true}",
                LoginRequest.class).getRememberMe());
        assertEquals(Boolean.TRUE, mapper.readValue("{\"username\":\"u\",\"password\":\"p\",\"rememberMe\":true}",
                LoginRequest.class).getRememberMe());
    }

    @Test
    void updateUser_shouldAcceptCamelCaseAdminFields() throws Exception {
        UpdateUserRequest request = mapper.readValue(
                "{\"userStatus\":\"banned\",\"storageLimit\":1024,\"uploadLimit\":50}", UpdateUserRequest.class);
        assertEquals("banned", request.getUserStatus());
        assertEquals(1024L, request.getStorageLimit());
        assertEquals(50, request.getUploadLimit());
    }

    @Test
    void notificationSettings_shouldAcceptCamelCaseFields() throws Exception {
        NotificationSettingsDTO dto = mapper.readValue(
                "{\"emailNotify\":true,\"browserNotify\":false,\"storageAlert\":true,\"shareNotify\":false}",
                NotificationSettingsDTO.class);
        assertEquals(Boolean.TRUE, dto.getEmailNotify());
        assertEquals(Boolean.FALSE, dto.getBrowserNotify());
        assertEquals(Boolean.TRUE, dto.getStorageAlert());
        assertEquals(Boolean.FALSE, dto.getShareNotify());
    }
}