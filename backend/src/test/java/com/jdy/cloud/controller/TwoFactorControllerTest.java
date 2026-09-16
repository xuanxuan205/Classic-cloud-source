package com.jdy.cloud.controller;

import com.jdy.cloud.exception.GlobalExceptionHandler;
import com.jdy.cloud.model.User;
import com.jdy.cloud.repository.UserRepository;
import com.jdy.cloud.security.DeviceIdentityResolver;
import com.jdy.cloud.security.UserPrincipal;
import com.jdy.cloud.service.AuthService;
import com.jdy.cloud.service.TotpService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * IronWall v1.39.0: 2FA 关闭双因子契约测试（闭环）。
 * 关闭必须 密码 + 当前 TOTP；缺少/错误任一因子都不得关闭。
 */
@ExtendWith(MockitoExtension.class)
class TwoFactorControllerTest {

    @Mock private TotpService totpService;
    @Mock private AuthService authService;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private UserRepository userRepository;
    @Mock private DeviceIdentityResolver deviceIdentityResolver;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        TwoFactorController controller = new TwoFactorController(totpService, authService, passwordEncoder, userRepository, deviceIdentityResolver);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new GlobalExceptionHandler())
                .setCustomArgumentResolvers(new org.springframework.security.web.method.annotation.AuthenticationPrincipalArgumentResolver())
                .build();
        UserPrincipal principal = new UserPrincipal(1L, "tester", "user");
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(principal, null, java.util.List.of());
        SecurityContextHolder.getContext().setAuthentication(auth);

        User user = new User();
        user.setId(1L);
        user.setUsername("tester");
        user.setPassword("$2a$10$hashed");
        lenient().when(userRepository.findById(1L)).thenReturn(Optional.of(user));
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    private String body(String password, String code) throws Exception {
        Map<String, String> m = new LinkedHashMap<>();
        if (password != null) m.put("password", password);
        if (code != null) m.put("code", code);
        return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(m);
    }

    @Test
    void disable_shouldRejectWrongPassword() throws Exception {
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);
        mockMvc.perform(post("/api/auth/2fa/disable").contentType("application/json")
                        .content(body("bad-password", "123456")))
                .andExpect(status().isUnauthorized());
        verify(totpService, never()).disable(anyLong());
    }

    @Test
    void disable_shouldRequireTotpCode_when2faEnabled() throws Exception {
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
        when(totpService.isEnabled(1L)).thenReturn(true);
        mockMvc.perform(post("/api/auth/2fa/disable").contentType("application/json")
                        .content(body("good-password", null)))
                .andExpect(status().isBadRequest());
        verify(totpService, never()).disable(anyLong());
    }

    @Test
    void disable_shouldRejectWrongTotpCode() throws Exception {
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
        when(totpService.isEnabled(1L)).thenReturn(true);
        when(totpService.verifyAndConsumeLoginCode(1L, "654321")).thenReturn(false);
        mockMvc.perform(post("/api/auth/2fa/disable").contentType("application/json")
                        .content(body("good-password", "654321")))
                .andExpect(status().isBadRequest());
        verify(totpService, never()).disable(anyLong());
    }

    @Test
    void disable_shouldSucceedWithDualFactor() throws Exception {
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
        when(totpService.isEnabled(1L)).thenReturn(true);
        when(totpService.verifyAndConsumeLoginCode(1L, "123456")).thenReturn(true);
        mockMvc.perform(post("/api/auth/2fa/disable").contentType("application/json")
                        .content(body("good-password", "123456")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        verify(totpService).disable(1L);
    }

    @Test
    void disable_shouldNotRequireTotp_when2faNotEnabled() throws Exception {
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
        when(totpService.isEnabled(1L)).thenReturn(false);
        mockMvc.perform(post("/api/auth/2fa/disable").contentType("application/json")
                        .content(body("good-password", null)))
                .andExpect(status().isOk());
        verify(totpService).disable(1L);
    }
}
