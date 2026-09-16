package com.jdy.cloud.controller;

import com.jdy.cloud.dto.*;
import com.jdy.cloud.util.ClientIpUtils;
import com.jdy.cloud.exception.ErrorCode;
import com.jdy.cloud.security.UserPrincipal;
import com.jdy.cloud.security.DeviceIdentityResolver;
import com.jdy.cloud.security.ApiCryptoFilter;
import com.jdy.cloud.service.AuthService;
import com.jdy.cloud.repository.UserRepository;
import com.jdy.cloud.repository.AnnouncementRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.web.multipart.MultipartFile;
import java.util.Map;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;
    private final AnnouncementRepository announcementRepository;
    private final DeviceIdentityResolver deviceIdentityResolver;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@Valid @RequestBody LoginRequest request,
                                                             HttpServletRequest httpRequest) {
        String ip = ClientIpUtils.getClientIp(httpRequest);
        String device = httpRequest.getHeader("User-Agent");
        DeviceIdentityResolver.Identity identity = deviceIdentityResolver.resolve(httpRequest);
        LoginResponse result = authService.login(request, ip, device,
                identity.fingerprint(), identity.deviceId(), identity.signature());
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<LoginResponse>> register(@Valid @RequestBody RegisterRequest request) {
        LoginResponse result = authService.register(request);
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    /**
     * IronWall v1.39.0: 邮箱枚举收敛（闭环）——未授权仅返回格式校验，
     * registered 一律为 null（未知态）；注册状态以 /register 的权威二次校验为准，
     * 匿名枚举面归零。
     */
    @GetMapping("/check-email")
    public ResponseEntity<ApiResponse<Map<String, Object>>> checkEmail(@RequestParam String email) {
        boolean formatOk = email != null && !email.isBlank()
                && email.matches("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$");
        if (!formatOk) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error(ErrorCode.BAD_REQUEST.getCode(), "邮箱格式不正确"));
        }
        Map<String, Object> data = new java.util.LinkedHashMap<>();
        data.put("checked", true);
        data.put("format_ok", true);
        data.put("registered", null);
        data.put("message", "邮箱格式正确");
        return ResponseEntity.ok(ApiResponse.ok(data));
    }

    @PostMapping("/send-code")
    public ResponseEntity<ApiResponse<Void>> sendCode(@Valid @RequestBody EmailCodeRequest request,
                                                       HttpServletRequest httpRequest) {
        authService.sendVerificationCode(request, getClientIp(httpRequest));
        return ResponseEntity.ok(ApiResponse.ok("验证码已发送", null));
    }

    @PostMapping("/verify-code")
    public ResponseEntity<ApiResponse<Void>> verifyCode(@Valid @RequestBody EmailCodeRequest request) {
        authService.verifyCode(request);
        return ResponseEntity.ok(ApiResponse.ok("验证成功", null));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<Void>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request);
        return ResponseEntity.ok(ApiResponse.ok("密码重置成功", null));
    }

    @GetMapping("/user-info")
    public ResponseEntity<ApiResponse<LoginResponse>> getUserInfo(@AuthenticationPrincipal UserPrincipal principal) {
        LoginResponse result = authService.getUserInfo(principal.getUserId());
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    @PostMapping("/change-password")
    public ResponseEntity<ApiResponse<Void>> changePassword(@AuthenticationPrincipal UserPrincipal principal,
                                                             @Valid @RequestBody ChangePasswordRequest request) {
        authService.changePassword(principal.getUserId(), request);
        return ResponseEntity.ok(ApiResponse.ok("密码修改成功", null));
    }

    @GetMapping("/login-history")
    public ResponseEntity<ApiResponse<Object>> getLoginHistory(@AuthenticationPrincipal UserPrincipal principal) {
        return ResponseEntity.ok(ApiResponse.ok(authService.getLoginHistory(principal.getUserId())));
    }

    @PostMapping("/update-email")
    public ResponseEntity<ApiResponse<Void>> updateEmail(@AuthenticationPrincipal UserPrincipal principal,
                                                          @Valid @RequestBody UpdateEmailRequest request) {
        authService.updateEmail(principal.getUserId(), request);
        return ResponseEntity.ok(ApiResponse.ok("邮箱修改成功", null));
    }

    @PostMapping("/update-username")
    public ResponseEntity<ApiResponse<Void>> updateUsername(@AuthenticationPrincipal UserPrincipal principal,
                                                             @Valid @RequestBody UpdateUsernameRequest request) {
        authService.updateUsername(principal.getUserId(), request);
        return ResponseEntity.ok(ApiResponse.ok("用户名修改成功", null));
    }

    @PostMapping("/upload-avatar")
    public ResponseEntity<ApiResponse<Map<String, String>>> uploadAvatar(@AuthenticationPrincipal UserPrincipal principal,
                                                                           @RequestParam("avatar") MultipartFile file,
                                                                           @RequestHeader(value = ApiCryptoFilter.FILE_HASH_HEADER, required = false) String fileHash) throws Exception {
        String avatarUrl = authService.uploadAvatar(principal.getUserId(), file, fileHash);
        return ResponseEntity.ok(ApiResponse.ok(Map.of("avatarUrl", avatarUrl == null ? "" : avatarUrl)));
    }

    /**
     * IronWall v1.43.0: 登出吊销——服务端递增 token_version，
     * 旧 JWT（含已泄露副本）在下一次请求立即失效（闭环）。
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@AuthenticationPrincipal UserPrincipal principal) {
        authService.logout(principal.getUserId());
        return ResponseEntity.ok(ApiResponse.ok("已安全退出", null));
    }

    @PostMapping("/delete-account")
    public ResponseEntity<ApiResponse<Void>> deleteAccount(@AuthenticationPrincipal UserPrincipal principal,
                                                            @Valid @RequestBody DeleteAccountRequest request) {
        authService.deleteAccount(principal.getUserId(), request);
        return ResponseEntity.ok(ApiResponse.ok("账号已注销", null));
    }

    @PostMapping("/verify-email")
    public ResponseEntity<ApiResponse<Void>> sendVerificationEmail(@AuthenticationPrincipal UserPrincipal principal,
                                                                     HttpServletRequest httpRequest) {
        authService.sendVerificationEmail(principal.getUserId(), getClientIp(httpRequest));
        return ResponseEntity.ok(ApiResponse.ok("验证邮件已发送", null));
    }

    @GetMapping("/notification-settings")
    public ResponseEntity<ApiResponse<NotificationSettingsDTO>> getNotificationSettings(@AuthenticationPrincipal UserPrincipal principal) {
        return ResponseEntity.ok(ApiResponse.ok(authService.getNotificationSettings(principal.getUserId())));
    }

    @PutMapping("/notification-settings")
    public ResponseEntity<ApiResponse<Void>> updateNotificationSettings(@AuthenticationPrincipal UserPrincipal principal,
                                                                          @RequestBody NotificationSettingsDTO dto) {
        authService.updateNotificationSettings(principal.getUserId(), dto);
        return ResponseEntity.ok(ApiResponse.ok("通知设置已更新", null));
    }

    @GetMapping("/devices")
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getDevices(@AuthenticationPrincipal UserPrincipal principal) {
        return ResponseEntity.ok(ApiResponse.ok(authService.getDevices(principal.getUserId())));
    }

    @DeleteMapping("/devices/{deviceId}")
    public ResponseEntity<ApiResponse<Void>> revokeDevice(@AuthenticationPrincipal UserPrincipal principal,
                                                           @PathVariable Long deviceId) {
        authService.revokeDevice(principal.getUserId(), deviceId);
        return ResponseEntity.ok(ApiResponse.ok("设备已撤销", null));
    }

    @GetMapping("/announcements")
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getPublicAnnouncements() {
        // 置顶公告在前（各自按 created_at 降序），合计最多 10 条；定时(scheduled)与草稿不外露
        List<com.jdy.cloud.model.Announcement> pinned = announcementRepository.findByStatusOrderByCreatedAtDesc("pinned");
        List<com.jdy.cloud.model.Announcement> published = announcementRepository.findByStatusOrderByCreatedAtDesc("published");
        java.util.List<com.jdy.cloud.model.Announcement> merged = new java.util.ArrayList<>();
        merged.addAll(pinned);
        merged.addAll(published);
        if (merged.size() > 10) {
            merged = merged.subList(0, 10);
        }
        List<Map<String, Object>> list = new java.util.ArrayList<>();
        for (com.jdy.cloud.model.Announcement a : merged) {
            Map<String, Object> m = new java.util.LinkedHashMap<>();
            m.put("id", a.getId());
            m.put("title", com.jdy.cloud.util.SecurityUtils.stripHtmlTags(a.getTitle()));
            m.put("content", com.jdy.cloud.util.SecurityUtils.stripHtmlTags(a.getContent()));
            m.put("status", a.getStatus());
            m.put("created_at", a.getCreatedAt() != null ? a.getCreatedAt().toString() : "");
            list.add(m);
        }
        return ResponseEntity.ok(ApiResponse.ok(list));
    }



    private String getClientIp(HttpServletRequest request) {
        return ClientIpUtils.getClientIp(request);
    }
}
