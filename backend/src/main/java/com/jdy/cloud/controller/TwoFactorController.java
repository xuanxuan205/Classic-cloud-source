package com.jdy.cloud.controller;

import com.jdy.cloud.dto.ApiResponse;
import com.jdy.cloud.dto.LoginResponse;
import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.ErrorCode;
import com.jdy.cloud.security.UserPrincipal;
import com.jdy.cloud.service.AuthService;
import com.jdy.cloud.service.TotpService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * IronWall v1.28.0: 两步验证（TOTP）绑定与登录第二步。
 * 绑定流程：setup 生成密钥 -> 验证器 App 扫码/手动输入 -> confirm 用当前动态码确认启用。
 * IronWall v1.39.0: 关闭需要双因子——登录密码 + 当前 TOTP 动态码（闭环）。
 */
@RestController
@RequestMapping("/api/auth/2fa")
@RequiredArgsConstructor
@Slf4j
public class TwoFactorController {

    private final TotpService totpService;
    private final AuthService authService;
    private final PasswordEncoder passwordEncoder;
    private final com.jdy.cloud.repository.UserRepository userRepository;
    private final com.jdy.cloud.security.DeviceIdentityResolver deviceIdentityResolver;

    @GetMapping("/status")
    public ResponseEntity<ApiResponse<Map<String, Object>>> status(@AuthenticationPrincipal UserPrincipal principal) {
        return ResponseEntity.ok(ApiResponse.ok(totpService.status(principal.getUserId())));
    }

    @PostMapping("/setup")
    public ResponseEntity<ApiResponse<Map<String, String>>> setup(@AuthenticationPrincipal UserPrincipal principal) {
        String secret = totpService.generateSecret();
        totpService.savePending(principal.getUserId(), secret);
        return ResponseEntity.ok(ApiResponse.ok(Map.of(
                "secret", secret,
                "otpauth_uri", totpService.otpauthUri(secret, principal.getUsername()),
                "account", principal.getUsername()
        )));
    }

    @PostMapping("/confirm")
    public ResponseEntity<ApiResponse<Void>> confirm(@AuthenticationPrincipal UserPrincipal principal,
                                                     @RequestBody Map<String, String> body) {
        String code = body.get("code");
        if (code == null || !code.trim().matches("\\d{6}")) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "动态验证码格式不正确");
        }
        if (!totpService.confirm(principal.getUserId(), code.trim())) {
            throw new BusinessException(ErrorCode.CODE_ERROR.getCode(), "动态验证码错误，请与验证器 App 对时后重试");
        }
        return ResponseEntity.ok(ApiResponse.ok("两步验证已启用", null));
    }

    /**
     * IronWall v1.39.0: 关闭两步验证必须双因子——登录密码 + 当前 TOTP 动态码，
     * 杜绝密码泄露后被静默解除第二因子。2FA 未启用时不要求动态码（关闭为幂等空操作）。
     */
    @PostMapping("/disable")
    public ResponseEntity<ApiResponse<Void>> disable(@AuthenticationPrincipal UserPrincipal principal,
                                                     @RequestBody Map<String, String> body) {
        String password = body.get("password");
        String code = body.get("code");
        var user = userRepository.findById(principal.getUserId())
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        if (password == null || !passwordEncoder.matches(password, user.getPassword())) {
            throw new BusinessException(ErrorCode.WRONG_PASSWORD.getCode(), "密码错误，无法关闭两步验证");
        }
        if (totpService.isEnabled(principal.getUserId())) {
            if (code == null || !code.trim().matches("\\d{6}")) {
                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "请输入当前动态验证码");
            }
            if (!totpService.verifyAndConsumeLoginCode(principal.getUserId(), code.trim())) {
                throw new BusinessException(ErrorCode.CODE_ERROR.getCode(), "动态验证码错误或已被使用，请使用当前最新动态码");
            }
        }
        totpService.disable(principal.getUserId());
        log.warn("[IronWall] 2FA disabled with dual-factor for user={}", principal.getUserId());
        return ResponseEntity.ok(ApiResponse.ok("两步验证已关闭", null));
    }

    /** 登录第二步：中间令牌 + 动态码 -> 正式会话。 */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> completeLogin(@RequestBody Map<String, String> body,
                                                                    HttpServletRequest httpRequest) {
        String token = body.get("token");
        String code = body.get("code");
        if (token == null || token.isBlank()) {
            throw new BusinessException(ErrorCode.INVALID_TOKEN);
        }
        String fingerprint = deviceIdentityResolver.resolve(httpRequest).fingerprint();
        LoginResponse result = authService.completeTwoFactorLogin(token, code == null ? "" : code,
                com.jdy.cloud.util.ClientIpUtils.getClientIp(httpRequest), httpRequest.getHeader("User-Agent"), fingerprint);
        return ResponseEntity.ok(ApiResponse.ok(result));
    }
}
