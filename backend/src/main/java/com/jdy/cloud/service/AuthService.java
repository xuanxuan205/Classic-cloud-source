package com.jdy.cloud.service;

import com.jdy.cloud.dto.*;
import com.jdy.cloud.util.ImageSafety;
import com.jdy.cloud.util.SecurityUtils;
import com.jdy.cloud.util.StoragePaths;
import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.ErrorCode;
import com.jdy.cloud.model.LoginHistory;
import com.jdy.cloud.model.AuditLog;
import com.jdy.cloud.model.NotificationSettings;
import com.jdy.cloud.model.User;
import com.jdy.cloud.repository.LoginHistoryRepository;
import com.jdy.cloud.repository.AuditLogRepository;
import com.jdy.cloud.repository.NotificationSettingsRepository;
import com.jdy.cloud.repository.UserRepository;
import com.jdy.cloud.security.JwtTokenProvider;
import com.jdy.cloud.security.AttackGuardService;
import org.springframework.dao.DataIntegrityViolationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final EmailService emailService;
    private final AuditLogService auditLogService;
    private final LoginHistoryRepository loginHistoryRepository;
    private final VerificationCodeService verificationCodeService;
    private final com.jdy.cloud.security.TokenVersionService tokenVersionService;
private final NotificationSettingsRepository notificationSettingsRepository;
private final TotpService totpService;
private final ThreatIntelService threatIntelService;
    // IronWall v1.29.0: 账号三维联动（账号/设备/IP）——登录爆破时联动攻击引擎计分与设备锁定
    private final AttackGuardService attackGuardService;

    @Value("${app.storage.upload-dir:${UPLOAD_DIR:./uploads}}")
    private String uploadDir;

    // IronWall v1.3: verify-email 独立限频（60s 间隔 + 每小时最多 5 次）
    private static final Map<Long, VerifyEmailRecord> VERIFY_EMAIL_RECORDS = new ConcurrentHashMap<>();

    // IronWall v1.5: 登录失败按真实 IP 累计锁定（防 XFF 轮换 + 账号喷洒）
    // IronWall v1.7: 拆分为「账号+IP」与「IP 全局」双维度，避免单 IP 冷却拖垮该 IP 下所有正常用户
    private final Map<String, IpFailWindow> ipFailWindows = new ConcurrentHashMap<>();
    private final Map<String, IpFailWindow> ipGlobalFailWindows = new ConcurrentHashMap<>();
    // IronWall v1.29.0: 设备维登录失败窗口（同一设备换账号爆破）
    private final Map<String, IpFailWindow> deviceFailWindows = new ConcurrentHashMap<>();
    // IronWall v1.29.0: 账号跨IP分布式爆破证据（撞库）
    private final Map<String, AccountSpreadWindow> accountSpreadWindows = new ConcurrentHashMap<>();
    private static final int IP_FAIL_LIMIT = 10;
    private static final int IP_GLOBAL_FAIL_LIMIT = 30;
    private static final int DEVICE_FAIL_LIMIT = 10;
    private static final int ACCOUNT_SPREAD_MIN_IPS = 4;
    private static final long IP_FAIL_WINDOW_MS = 10 * 60_000L;
    private static final long IP_FAIL_BLOCK_MS = 10 * 60_000L;

    // IronWall v1.5: verify-email 按真实 IP 限频（防多账号轮换刷邮件）
    private final Map<String, VerifyEmailRecord> verifyEmailIpRecords = new ConcurrentHashMap<>();

    // IronWall v1.21.2: verify-email 每日配额（防长期邮件轰炸）
    private static final int MAX_VERIFY_EMAILS_PER_DAY = 10;

    public LoginResponse login(LoginRequest request, String ip, String device) {
        return login(request, ip, device, null, null, null);
    }

    /** IronWall v1.29.0: 登录三维联动（账号/设备/IP），携带设备身份记分。 */
    @Transactional
    public LoginResponse login(LoginRequest request, String ip, String device, String fingerprint, String deviceId,
                               String fingerprintSignature) {
        String loginId = request.getUsername() != null ? request.getUsername().trim() : "unknown";

        // IronWall v1.2: 防账号枚举 - 统一查询 + 恒时比对 + 统一响应
        User user = userRepository.findByLoginId(loginId).orElse(null);

        // 超大ID防护（19位以上数字直接按不存在处理，防止500）
        if (user == null && loginId.matches("^\\d{1,18}$")) {
            try {
                Long id = Long.parseLong(loginId);
                user = userRepository.findById(id).orElse(null);
            } catch (NumberFormatException ignored) { }
        }

        // 核心: 无论用户是否存在，都执行bcrypt（恒定时间），都返回相同错误
        String dummyHash = "$2a$10$abcdefghijklmnopqrstuvwxyz012345678901234567890123456789";
        if (user == null) {
            passwordEncoder.matches(request.getPassword(), dummyHash);
            recordDeviceFailure(fingerprint, deviceId, fingerprintSignature, ip, loginId, device);
            recordAccountSpread(loginId, ip, fingerprint, deviceId, fingerprintSignature, device);
            recordIpFailure(ip, loginId);
            throw new BusinessException(ErrorCode.WRONG_PASSWORD.getCode(), "用户名或密码错误");
        }

        // 账号锁定也统一返回（不泄露账号存在）
        if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(LocalDateTime.now())) {
            recordDeviceFailure(fingerprint, deviceId, fingerprintSignature, ip, loginId, device);
            recordAccountSpread(loginId, ip, fingerprint, deviceId, fingerprintSignature, device);
            recordIpFailure(ip, loginId);
            throw new BusinessException(ErrorCode.WRONG_PASSWORD.getCode(), "用户名或密码错误");
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            recordDeviceFailure(fingerprint, deviceId, fingerprintSignature, ip, loginId, device);
            recordAccountSpread(loginId, ip, fingerprint, deviceId, fingerprintSignature, device);
            recordIpFailure(ip, loginId);
            user.setLoginAttempts(user.getLoginAttempts() + 1);
            if (user.getLoginAttempts() >= 5) {
                user.setLockedUntil(LocalDateTime.now().plusMinutes(30));
            }
            userRepository.save(user);
            throw new BusinessException(ErrorCode.WRONG_PASSWORD.getCode(), "用户名或密码错误");
        }

        // IronWall v1.11: 被封禁账号在密码正确后统一拒绝（正确密码才透露封禁状态，杜绝枚举）
        if ("banned".equalsIgnoreCase(user.getUserStatus())) {
            throw new BusinessException(ErrorCode.ACCOUNT_BANNED.getCode(), ErrorCode.ACCOUNT_BANNED.getMessage());
        }

        user.setLoginAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);
        clearIpFailures(ip, loginId);
        clearDeviceFailures(deviceId != null ? deviceId : fingerprint);
        clearAccountSpread(loginId);

        // IronWall v1.28.0: 两步验证——密码正确但未过动态码时只发中间令牌（5 分钟有效）
        if (totpService.isEnabled(user.getId())) {
            LoginResponse pending = new LoginResponse();
            pending.setTwoFactorRequired(true);
            pending.setTwoFactorToken(jwtTokenProvider.generateTwoFactorToken(
                    user.getId(), user.getUsername(), deviceHashOf(user.getId(), fingerprint)));
            auditLogService.logLogin(user.getId(), ip, device, "2fa_pending");
            return pending;
        }

        boolean remember = request.getRememberMe() != null && request.getRememberMe();
        return issueSession(user, remember, ip, device);
    }

    /** IronWall v1.28.0: 两步验证第二步——校验中间令牌与动态码后签发正式会话。 */
    public LoginResponse completeTwoFactorLogin(String twoFactorToken, String code, String ip, String device) {
        return completeTwoFactorLogin(twoFactorToken, code, ip, device, null);
    }

    /**
     * IronWall v1.40.0: 中间令牌绑定发起登录时的设备指纹，第二步必须同设备完成；
     * 动态码一次性消费（150s 内同一码只可用一次）。
     */
    public LoginResponse completeTwoFactorLogin(String twoFactorToken, String code, String ip, String device, String fingerprint) {
        Long userId = jwtTokenProvider.getTwoFactorUserId(twoFactorToken);
        if (userId == null) {
            throw new BusinessException(ErrorCode.INVALID_TOKEN);
        }
        String boundHash = jwtTokenProvider.getTwoFactorDeviceHash(twoFactorToken);
        if (boundHash != null) {
            String currentHash = deviceHashOf(userId, fingerprint);
            if (!java.security.MessageDigest.isEqual(
                    boundHash.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    currentHash.getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
                throw new BusinessException(ErrorCode.CODE_ERROR.getCode(), "动态验证码错误或已过期");
            }
        }
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        if (!totpService.verifyAndConsumeLoginCode(userId, code)) {
            throw new BusinessException(ErrorCode.CODE_ERROR.getCode(), "动态验证码错误或已过期（每个动态码仅可使用一次）");
        }
        return issueSession(user, false, ip, device);
    }

    /** IronWall v1.45.0: 原始字节全文件 SHA-256（与前端 computeFileSha256 一致）。 */
    private String sha256HexOf(byte[] bytes) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    /** IronWall v1.40.0: 设备指纹与账号绑定哈希（换设备即不匹配）。 */
    private String deviceHashOf(Long userId, String fingerprint) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                    .digest((userId + "|" + (fingerprint == null ? "" : fingerprint))
                            .getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    /** 签发正式会话：JWT + 登录历史 + 审计 + 异地登录邮件提醒。 */
    private LoginResponse issueSession(User user, boolean remember, String ip, String device) {
        String token = jwtTokenProvider.generateToken(user.getId(), user.getUsername(), user.getRole(), remember, tokenVersionOf(user));
        // IronWall v1.15: remember-me 不再延长令牌寿命，响应体与真实 JWT 到期时间保持一致（默认 24 小时）
        LocalDateTime expiresAt = LocalDateTime.now().plusSeconds(jwtTokenProvider.getExpirationMs() / 1000);

        try {
            LoginHistory history = new LoginHistory();
            history.setUserId(user.getId());
            history.setIp(ip);
            history.setDevice(device);
            history.setStatus("success");
            loginHistoryRepository.save(history);
        } catch (Exception e) {
            log.warn("[IronWall] login history save failed: {}", e.getMessage());
        }

        auditLogService.logLogin(user.getId(), ip, device, "success");
        sendNewLocationAlertIfNeeded(user, ip, device);

        return buildLoginResponse(user, token, expiresAt);
    }

    /**
     * IronWall v1.27.5: 注册页邮箱自动识别（/api/auth/check-email 使用）。
     * 端点已纳入 RateLimitFilter 严格限流，注册接口同样二次校验，防止枚举滥用。
     */
    public boolean emailExists(String email) {
        if (email == null || email.isBlank()) {
            return false;
        }
        try {
            return userRepository.existsByEmail(email.trim());
        } catch (Exception e) {
            log.warn("[IronWall] email existence check failed: {}", e.getMessage());
            return false;
        }
    }

    public LoginResponse register(RegisterRequest request) {

        if (!SecurityUtils.isStrongPassword(request.getPassword())) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), SecurityUtils.getPasswordRequirementMessage());
        }

        // IronWall v1.3: 注册用户名白名单校验，拒绝 HTML/脚本字符
        if (!SecurityUtils.isSafeUsername(request.getUsername().trim())) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(),
                "用户名仅支持中英文、数字、下划线、短横线、点号和空格（2-30字符），且不能包含HTML或脚本字符");
        }

        // IronWall v1.21.2 F-01: 保留名黑名单，防止冒充官方身份
        if (SecurityUtils.isReservedUsername(request.getUsername().trim())) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "该用户名不可用，请更换用户名");
        }

        verificationCodeService.verify(request.getEmail(), request.getCode());

        // IronWall v1.10: verify the one-time email code BEFORE username/email checks,
        // so username enumeration requires a fresh valid code per probe (send-code is rate-limited).
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new BusinessException(ErrorCode.USERNAME_EXISTS);
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new BusinessException(ErrorCode.EMAIL_EXISTS);
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setVerificationStatus("verified");
        // IronWall v1.27.8: 注册随机 5 位数字 ID（00000-99999），约 20% 概率命中豹子/顺子/回文等靓号
        String userCode;
        int attempts = 0;
        do {
            userCode = rollUserIdCode();
            attempts++;
            // IronWall v1.47.6: 99999 为管理员固定靓号，普通用户注册永不占用
        } while ((userRepository.existsByUserCode(userCode) || "99999".equals(userCode)) && attempts < 100);
        user.setUserCode(userCode);
        try {
            userRepository.save(user);
        } catch (DataIntegrityViolationException e) {
            // IronWall v1.21.2 F-01: 并发注册撞唯一索引时给出友好提示
            throw new BusinessException(ErrorCode.USERNAME_EXISTS.getCode(), "用户名或邮箱已被占用");
        }

        auditLogService.logRegister(user.getId(), "system");

        String token = jwtTokenProvider.generateToken(user.getId(), user.getUsername(), user.getRole(), false, tokenVersionOf(user));
        LocalDateTime expiresAt = LocalDateTime.now().plusSeconds(jwtTokenProvider.getExpirationMs() / 1000);

        return buildLoginResponse(user, token, expiresAt);
    }

    /**
     * IronWall v1.27.8: 随机 5 位数字 ID，约 20% 概率从靓号池抽取，其余为 00000-99999 全随机。
     */
    private String rollUserIdCode() {
        if (Math.random() < 0.20) {
            return rollSpecialUserIdCode();
        }
        return String.format("%05d", (int) (Math.random() * 100000));
    }

    private String rollSpecialUserIdCode() {
        int pick = (int) (Math.random() * 100);
        if (pick < 35) {
            // 豹子：如 88888
            int d = (int) (Math.random() * 10);
            return "" + d + d + d + d + d;
        }
        if (pick < 70) {
            // 顺子：01234~56789 或 98765~43210
            boolean asc = Math.random() < 0.5;
            int start = asc ? (int) (Math.random() * 6) : 5 + (int) (Math.random() * 5);
            StringBuilder sb = new StringBuilder(5);
            for (int i = 0; i < 5; i++) {
                sb.append(asc ? (start + i) : (start - i));
            }
            return sb.toString();
        }
        if (pick < 90) {
            // 回文：如 12321
            int a = 1 + (int) (Math.random() * 9);
            int b = (int) (Math.random() * 10);
            int c = (int) (Math.random() * 10);
            return "" + a + b + c + b + a;
        }
        // 重复型：ABABA 或 AABBB
        int a = 1 + (int) (Math.random() * 9);
        int b = (int) (Math.random() * 10);
        return Math.random() < 0.5 ? "" + a + b + a + b + a : "" + a + a + b + b + b;
    }

    public void sendVerificationCode(EmailCodeRequest request, String clientIp) {
        verificationCodeService.sendCode(request.getEmail(), clientIp);
    }

    public void verifyCode(EmailCodeRequest request) {
        verificationCodeService.verify(request.getEmail(), request.getCode());
    }

    /**
     * IronWall v1.20: 重置密码防用户枚举。
     * 顺序固定：强密码校验 -> 验证码校验 -> 静默处理。
     * 邮箱不存在与重置成功返回完全相同的响应（验证码正确但用户不存在时同样回执成功文案），
     * 探测者无法从响应差异判断邮箱是否已注册；已注册用户重置后立即吊销全部旧 JWT。
     */
    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        if (!SecurityUtils.isStrongPassword(request.getNewPassword())) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), SecurityUtils.getPasswordRequirementMessage());
        }

        // 验证码校验先行且唯一：任何无效验证码统一返回同一文案，杜绝“用户存在性 + 验证码”双通道枚举
        try {
            verificationCodeService.verify(request.getEmail(), request.getCode());
        } catch (BusinessException e) {
            throw new BusinessException(ErrorCode.CODE_ERROR.getCode(), "验证码错误或已过期，请重新获取");
        }

        User user = userRepository.findByEmail(request.getEmail()).orElse(null);
        if (user == null) {
            // 邮箱未注册：不返回任何差异，仅记录 WARN 审计，维持与成功一致的响应
            log.warn("[IronWall] reset-password for unregistered email (silent): email={}", request.getEmail());
            return;
        }
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
        // IronWall v1.20: 重置密码后全部旧 JWT 立即失效
        tokenVersionService.bump(user.getId());
        auditLogService.logChangePassword(user.getId(), "system");
    }

    public LoginResponse getUserInfo(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));

        return buildLoginResponse(user, null, null);
    }

    @Transactional
    public void changePassword(Long userId, ChangePasswordRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
            throw new BusinessException(ErrorCode.WRONG_PASSWORD);
        }
        if (!SecurityUtils.isStrongPassword(request.getNewPassword())) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), SecurityUtils.getPasswordRequirementMessage());
        }
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
        // IronWall v1.20: 修改密码后旧 JWT 立即失效（银行级会话吊销）
        tokenVersionService.bump(user.getId());
        auditLogService.logChangePassword(user.getId(), "system");
    }

    private int tokenVersionOf(User user) {
        return user.getTokenVersion() == null ? 0 : user.getTokenVersion();
    }

    public List<Map<String, Object>> getLoginHistory(Long userId) {
        List<LoginHistory> histories = loginHistoryRepository
                .findByUserIdOrderByTimeDesc(userId, org.springframework.data.domain.PageRequest.of(0, 50)).getContent();
        List<Map<String, Object>> result = new ArrayList<>();
        for (LoginHistory h : histories) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", h.getId());
            m.put("time", h.getTime() != null ? h.getTime().toString() : "");
            m.put("ip", h.getIp());
            m.put("device", h.getDevice());
            m.put("status", h.getStatus());
            result.add(m);
        }
        return result;
    }

    @Transactional
    public void updateUsername(Long userId, UpdateUsernameRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        // IronWall v1.43.0: 敏感操作统一二次认证——改用户名必须验证当前密码，
        // 与「关闭 2FA 需密码」策略对齐。
        if (request.getPassword() == null || request.getPassword().isBlank()
                || !passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BusinessException(ErrorCode.UNAUTHORIZED.getCode(), "密码错误，无法修改用户名");
        }
        String newUsername = request.getUsername().trim();
        if (!SecurityUtils.isSafeUsername(newUsername)) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(),
                "用户名仅支持中英文、数字、下划线、短横线、点号和空格（2-30字符），且不能包含HTML或脚本字符");
        }
        if (newUsername.length() < 2 || newUsername.length() > 30) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "用户名长度需在2-30个字符之间");
        }
        // IronWall v1.21.2 F-01: 保留名黑名单，防止改名为 admin/root 等官方身份
        if (SecurityUtils.isReservedUsername(newUsername)) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "该用户名不可用，请更换用户名");
        }
        userRepository.findByUsername(newUsername).ifPresent(u -> {
            if (!u.getId().equals(userId)) {
                throw new BusinessException(ErrorCode.USERNAME_EXISTS);
            }
        });
        String oldUsername = user.getUsername();
        user.setUsername(newUsername);
        try {
            userRepository.save(user);
        } catch (DataIntegrityViolationException e) {
            // IronWall v1.21.2 F-01: 并发改名撞唯一索引时给出友好提示
            throw new BusinessException(ErrorCode.USERNAME_EXISTS);
        }
        auditLogService.logUpdateProfile(userId, "修改用户名: " + oldUsername + " -> " + newUsername, "system");
    }

    /** IronWall v1.43.0: 登出吊销——token_version 递增使全部旧 JWT 立即失效。 */
    public void logout(Long userId) {
        if (userId != null) {
            tokenVersionService.bump(userId);
        }
    }

    @Transactional
    public void updateEmail(Long userId, UpdateEmailRequest request) {
        log.info("updateEmail called: userId={}, email={}", userId, request.getEmail());
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));

        if (userRepository.existsByEmail(request.getEmail())) {
            // IronWall v1.21: 不区分“已注册/不可用”，消除 update-email 账号枚举
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "该邮箱不可用，请更换邮箱");
        }

        verificationCodeService.verify(request.getEmail(), request.getCode());

        user.setEmail(request.getEmail());
        user.setVerificationStatus("verified");
        userRepository.save(user);
        auditLogService.logUpdateProfile(userId, "邮箱", "system");
    }

    // IronWall v1.13: @Modifying(flushAutomatically=true) queries REQUIRE an active
    // transaction; without this annotation every avatar upload died with 500.
    @Transactional
    public String uploadAvatar(Long userId, MultipartFile file) {
        return uploadAvatar(userId, file, null);
    }

    /**
     * IronWall v1.45.0: expectedFileHash 为 X-Api-File-Hash（全文件 SHA-256，
     * HMAC 已绑定），对收到的原始字节重算整文件哈希复核；头像会被 ImageIO 重编码，
     * 故比对对象是收到的原始 multipart 字节而非落盘文件。
     */
    @Transactional
    public String uploadAvatar(Long userId, MultipartFile file, String expectedFileHash) {
        log.info("uploadAvatar called: userId={}", userId);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));

        if (file == null || file.isEmpty()) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "仅支持图片格式");
        }

        String contentType = file.getContentType();
        if (contentType == null || !contentType.startsWith("image/")) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "仅支持图片格式");
        }

        if (file.getSize() > 5 * 1024 * 1024) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "图片大小不能超过5MB");
        }

        // IronWall v1.8: 头像处理全链路兜底。
        // ImageIO 重编码失败（精简 JRE 缺 AWT / 图片损坏）时退回纯字节魔数校验，
        // 只接受真实光栅图片；SVG/HTML 伪装内容依旧被拒绝（保持有效）。
        byte[] fileBytes;
        try {
            fileBytes = file.getBytes();
        } catch (IOException e) {
            log.error("uploadAvatar read failed: {}", e.getMessage(), e);
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "无法识别的图片格式");
        }
        if (expectedFileHash != null && !expectedFileHash.isBlank()) {
            String actualHash = sha256HexOf(fileBytes);
            boolean match = !actualHash.isEmpty() && MessageDigest.isEqual(
                    actualHash.getBytes(StandardCharsets.UTF_8),
                    expectedFileHash.trim().toLowerCase(java.util.Locale.ROOT).getBytes(StandardCharsets.UTF_8));
            if (!match) {
                log.warn("[IronWall] avatar integrity mismatch: userId={}", userId);
                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "头像完整性校验失败，请重试");
            }
        }

        String storedExt;
        byte[] safeBytes;
        byte[] reencoded = ImageSafety.reencodeToPng(fileBytes);
        if (reencoded != null) {
            safeBytes = reencoded;
            storedExt = "png";
        } else {
            String fallbackFormat = ImageSafety.detectRasterFormat(fileBytes);
            if (fallbackFormat == null) {
                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "无法识别的图片格式");
            }
            safeBytes = fileBytes;
            storedExt = fallbackFormat;
        }

        final long newSize = safeBytes.length;
        // IronWall v1.12: 头像计入存储配额。
        // delta = 新头像大小 - 已计入配额的旧头像大小（avatar_size 自愈列保证账本可追溯），
        // 旧头像文件在提交成功后删除，任何账号只保留一份当前头像，杜绝磁盘无限增长。
        long oldCountedSize = user.getAvatarSize() == null ? 0L : user.getAvatarSize();
        final long delta = newSize - oldCountedSize;
        Path oldPath = resolveExistingAvatar(user.getAvatar());

        try {
            String storedName = "avatar_" + userId + "_" + System.currentTimeMillis() + "." + storedExt;

            // IronWall v1.9: 主目录写不进时自动退回兜底目录（tmpdir/classic-cloud/avatars），
            // 上传与读取共用同一候选列表，任何服务器环境下头像功能都自愈可用
            Path writtenPath = null;
            IOException lastError = null;
            boolean written = false;
            for (Path avatarPath : StoragePaths.avatarDirs(uploadDir)) {
                try {
                    Files.createDirectories(avatarPath);
                    Path targetPath = avatarPath.resolve(storedName).normalize();
                    if (!targetPath.startsWith(avatarPath)) {
                        continue;
                    }
                    Files.write(targetPath, safeBytes);
                    writtenPath = targetPath;
                    written = true;
                    break;
                } catch (IOException | SecurityException e) {
                    lastError = new IOException("avatar write failed: " + e.getMessage());
                    log.warn("uploadAvatar write failed on dir {}, trying next: {}", avatarPath, e.getMessage());
                }
            }
            if (!written) {
                log.error("uploadAvatar all dirs failed", lastError);
                throw new BusinessException(ErrorCode.INTERNAL_ERROR.getCode(), "头像保存失败，请稍后重试");
            }

            final String avatarUrl = "/api/files/avatar/" + storedName;
            synchronized (avatarLockFor(userId)) {
                // IronWall v1.13: quota + metadata updates now run inside the transaction above
                // 原子扣减配额；0 行 = 配额不足或用户不存在，回滚已写文件
                int updated = userRepository.incrementStorageUsedWithinLimit(userId, delta);
                if (updated == 0) {
                    deleteQuietly(writtenPath);
                    throw new BusinessException(ErrorCode.STORAGE_FULL);
                }
                // 原子更新头像元数据（整实体 save 会覆盖并发更新的计数，改用列级 UPDATE）
                // IronWall v1.13: graceful degradation when avatar_size column is missing:
                // JPQL -> native with avatar_size -> URL-only (never a 500 again)
                int avatarUpdated;
                try {
                    avatarUpdated = userRepository.updateAvatar(userId, avatarUrl, newSize);
                } catch (Exception jpqlFailure) {
                    log.warn("uploadAvatar JPQL update failed (avatar_size column may be missing), trying native fallback: {}", jpqlFailure.getMessage());
                    avatarUpdated = tryUpdateAvatarNative(userId, avatarUrl, newSize);
                }
                if (avatarUpdated == 0) {
                    userRepository.incrementStorageUsed(userId, -delta);
                    deleteQuietly(writtenPath);
                    throw new BusinessException(ErrorCode.USER_NOT_FOUND);
                }
            }

            // 提交成功后删除旧头像文件 + 清理同账号历史残留，磁盘只保留当前一份
            if (oldPath != null) {
                deleteQuietly(oldPath);
            }
            cleanupOrphanAvatars(userId, storedName);

            auditLogService.logUpdateProfile(userId, "\u5934\u50cf", "system");
            return avatarUrl;
        } catch (BusinessException e) {
            throw e;
        } catch (Exception e) {
            // 不向客户端泄漏服务器路径等内部细节
            log.error("uploadAvatar storage failed: {}", e.getMessage(), e);
            throw new BusinessException(ErrorCode.INTERNAL_ERROR.getCode(), "头像保存失败，请稍后重试");
        }
    }

    // IronWall v1.12: 头像配额与磁盘清理辅助
    // IronWall v1.13: degradation chain for avatar metadata column-level updates
    private int tryUpdateAvatarNative(Long userId, String avatarUrl, long newSize) {
        try {
            return userRepository.updateAvatarNative(userId, avatarUrl, newSize);
        } catch (Exception nativeFailure) {
            log.warn("uploadAvatar native update with avatar_size failed, degrading to URL-only update: {}", nativeFailure.getMessage());
            try {
                return userRepository.updateAvatarUrlOnly(userId, avatarUrl);
            } catch (Exception urlOnlyFailure) {
                log.error("uploadAvatar URL-only update failed: {}", urlOnlyFailure.getMessage(), urlOnlyFailure);
                return 0;
            }
        }
    }

    private static final Object[] AVATAR_LOCKS = new Object[64];
    static {
        for (int i = 0; i < AVATAR_LOCKS.length; i++) {
            AVATAR_LOCKS[i] = new Object();
        }
    }

    private Object avatarLockFor(Long userId) {
        long id = userId == null ? 0L : userId;
        return AVATAR_LOCKS[(int) (Math.floorMod(id, AVATAR_LOCKS.length))];
    }

    private Path resolveExistingAvatar(String avatarUrl) {
        if (avatarUrl == null || avatarUrl.isBlank()) return null;
        String filename = avatarUrl.substring(avatarUrl.lastIndexOf('/') + 1);
        if (filename.isBlank() || filename.contains("..") || filename.contains("\\") || filename.contains("/")) return null;
        for (Path dir : StoragePaths.avatarDirs(uploadDir)) {
            Path candidate = dir.resolve(filename).normalize();
            if (candidate.startsWith(dir) && Files.exists(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private void deleteQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException e) {
            log.warn("avatar file delete failed: {} - {}", path, e.getMessage());
        }
    }

    private void cleanupOrphanAvatars(Long userId, String keepName) {
        String prefix = "avatar_" + userId + "_";
        for (Path dir : StoragePaths.avatarDirs(uploadDir)) {
            try (var stream = Files.list(dir)) {
                stream.filter(p -> p.getFileName().toString().startsWith(prefix))
                      .filter(p -> !p.getFileName().toString().equals(keepName))
                      .forEach(this::deleteQuietly);
            } catch (IOException e) {
                log.warn("orphan avatar scan failed on {}: {}", dir, e.getMessage());
            }
        }
    }


    public void deleteAccount(Long userId, DeleteAccountRequest request) {
        log.info("deleteAccount called: userId={}", userId);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BusinessException(ErrorCode.WRONG_PASSWORD);
        }

        userRepository.delete(user);
        auditLogService.logAdminAction(user.getId(), "delete_account", "user", user.getUsername(), "注销了账号", "system");
    }

    public void sendVerificationEmail(Long userId, String clientIp) {
        log.info("sendVerificationEmail called: userId={}", userId);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        VerifyEmailRecord record = VERIFY_EMAIL_RECORDS.computeIfAbsent(userId, k -> new VerifyEmailRecord());
        synchronized (record) {
            long now = System.currentTimeMillis();
            if (now - record.windowStart > 3600_000L) {
                record.windowStart = now;
                record.hourCount = 0;
            }
            if (record.lastSent > 0 && now - record.lastSent < 60_000L) {
                throw new BusinessException(ErrorCode.CODE_TOO_FREQUENT);
            }
            if (record.hourCount >= 5) {
                throw new BusinessException(ErrorCode.TOO_MANY_REQUESTS.getCode(), "验证邮件发送过于频繁，请1小时后再试");
            }
            if (now - record.dayStart > 86_400_000L) {
                record.dayStart = now;
                record.dayCount = 0;
            }
            if (record.dayCount >= MAX_VERIFY_EMAILS_PER_DAY) {
                throw new BusinessException(ErrorCode.TOO_MANY_REQUESTS.getCode(), "验证邮件发送过于频繁，请明天再试");
            }
            record.lastSent = now;
            record.hourCount++;
            record.dayCount++;
        }

        String ipKey = (clientIp == null || clientIp.isBlank()) ? "unknown" : clientIp.trim();
        VerifyEmailRecord ipRecord = verifyEmailIpRecords.computeIfAbsent(ipKey, k -> new VerifyEmailRecord());
        synchronized (ipRecord) {
            long now = System.currentTimeMillis();
            if (now - ipRecord.windowStart > 3600_000L) {
                ipRecord.windowStart = now;
                ipRecord.hourCount = 0;
            }
            if (ipRecord.lastSent > 0 && now - ipRecord.lastSent < 60_000L) {
                throw new BusinessException(ErrorCode.CODE_TOO_FREQUENT);
            }
            if (ipRecord.hourCount >= 5) {
                throw new BusinessException(ErrorCode.TOO_MANY_REQUESTS.getCode(), "验证邮件发送过于频繁，请1小时后再试");
            }
            if (now - ipRecord.dayStart > 86_400_000L) {
                ipRecord.dayStart = now;
                ipRecord.dayCount = 0;
            }
            if (ipRecord.dayCount >= MAX_VERIFY_EMAILS_PER_DAY) {
                throw new BusinessException(ErrorCode.TOO_MANY_REQUESTS.getCode(), "验证邮件发送过于频繁，请明天再试");
            }
            ipRecord.lastSent = now;
            ipRecord.hourCount++;
            ipRecord.dayCount++;
        }

        verificationCodeService.sendCode(user.getEmail(), "auth-user-" + userId);
    }

    private void recordIpFailure(String ip, String loginId) {
        String ipKey = (ip == null || ip.isBlank()) ? "unknown" : ip.trim();
        String pairKey = ipKey + "|u:" + ((loginId == null || loginId.isBlank()) ? "unknown" : loginId.trim());
        IpFailWindow w = ipFailWindows.computeIfAbsent(pairKey, k -> new IpFailWindow());
        synchronized (w) {
            long now = System.currentTimeMillis();
            if (now < w.blockedUntil) {
                throw new BusinessException(ErrorCode.TOO_MANY_REQUESTS.getCode(), "登录失败次数过多，请10分钟后再试");
            }
            if (now - w.windowStart > IP_FAIL_WINDOW_MS) {
                w.windowStart = now;
                w.count = 0;
            }
            w.count++;
            if (w.count >= IP_FAIL_LIMIT) {
                w.blockedUntil = now + IP_FAIL_BLOCK_MS;
                throw new BusinessException(ErrorCode.TOO_MANY_REQUESTS.getCode(), "登录失败次数过多，请10分钟后再试");
            }
        }

        IpFailWindow gw = ipGlobalFailWindows.computeIfAbsent(ipKey, k -> new IpFailWindow());
        synchronized (gw) {
            long now = System.currentTimeMillis();
            if (now < gw.blockedUntil) {
                throw new BusinessException(ErrorCode.TOO_MANY_REQUESTS.getCode(), "登录失败次数过多，请10分钟后再试");
            }
            if (now - gw.windowStart > IP_FAIL_WINDOW_MS) {
                gw.windowStart = now;
                gw.count = 0;
            }
            gw.count++;
            if (gw.count >= IP_GLOBAL_FAIL_LIMIT) {
                gw.blockedUntil = now + IP_FAIL_BLOCK_MS;
                throw new BusinessException(ErrorCode.TOO_MANY_REQUESTS.getCode(), "登录失败次数过多，请10分钟后再试");
            }
        }
    }

    private void clearIpFailures(String ip, String loginId) {
        String ipKey = (ip == null || ip.isBlank()) ? "unknown" : ip.trim();
        String pairKey = ipKey + "|u:" + ((loginId == null || loginId.isBlank()) ? "unknown" : loginId.trim());
        ipFailWindows.remove(pairKey);
    }

    // ========== IronWall v1.29.0: 账号三维联动 ==========

    /** 设备维登录失败窗口：同一设备换账号爆破达到阈值时联动攻击引擎计分（触发封禁即锁设备）。 */
    private void recordDeviceFailure(String fingerprint, String deviceId, String fingerprintSignature,
                                     String ip, String loginId, String device) {
        String identity = deviceId != null ? deviceId : fingerprint;
        if (identity == null || identity.length() < 16 || identity.length() > 128) return;
        IpFailWindow w = deviceFailWindows.computeIfAbsent(identity, k -> new IpFailWindow());
        boolean trip = false;
        synchronized (w) {
            long now = System.currentTimeMillis();
            if (now - w.windowStart > IP_FAIL_WINDOW_MS) {
                w.windowStart = now;
                w.count = 0;
            }
            w.count++;
            trip = w.count >= DEVICE_FAIL_LIMIT;
        }
        if (trip && attackGuardService != null) {
            try {
                attackGuardService.recordWeighted(ip, AttackGuardService.TYPE_TOOL,
                        "设备登录爆破:" + ((loginId == null || loginId.isBlank()) ? "unknown" : loginId.trim()),
                        "/api/auth/login", device, "POST", false, 10,
                        fingerprint, deviceId, fingerprintSignature);
            } catch (Exception e) {
                log.warn("[IronWall] device brute-force escalation failed: {}", e.getMessage());
            }
        }
    }

    private void clearDeviceFailures(String identity) {
        if (identity != null && identity.length() >= 16 && identity.length() <= 128) {
            deviceFailWindows.remove(identity);
        }
    }

    /** 账号跨IP分布式爆破证据：≥4 个不同 IP 在窗口内失败 → 锁账号 30 分钟并联动所有参与 IP 计分。 */
    private void recordAccountSpread(String loginId, String ip, String fingerprint, String deviceId,
                                     String fingerprintSignature, String device) {
        String accountKey = (loginId == null || loginId.isBlank()) ? "unknown" : loginId.trim();
        String ipKey = (ip == null || ip.isBlank()) ? "unknown" : ip.trim();
        AccountSpreadWindow w = accountSpreadWindows.computeIfAbsent(accountKey, k -> new AccountSpreadWindow());
        boolean trip = false;
        synchronized (w) {
            long now = System.currentTimeMillis();
            if (now - w.windowStart > IP_FAIL_WINDOW_MS) {
                w.windowStart = now;
                w.ips.clear();
                w.fails = 0;
                w.locked = false;
            }
            w.ips.add(ipKey);
            w.fails++;
            trip = !w.locked && w.fails >= ACCOUNT_SPREAD_MIN_IPS && w.ips.size() >= ACCOUNT_SPREAD_MIN_IPS;
            if (trip) {
                w.locked = true;
            }
        }
        if (!trip) return;
        // 锁账号 30 分钟（统一错误响应，不泄露账号存在性）
        try {
            User u = userRepository.findByLoginId(accountKey).orElse(null);
            if (u == null && accountKey.matches("^\\d{1,18}$")) {
                try {
                    u = userRepository.findById(Long.parseLong(accountKey)).orElse(null);
                } catch (NumberFormatException ignored) { }
            }
            if (u != null) {
                u.setLockedUntil(LocalDateTime.now().plusMinutes(30));
                userRepository.save(u);
            }
        } catch (Exception e) {
            log.warn("[IronWall] credential stuffing account lock failed: {}", e.getMessage());
        }
        if (attackGuardService != null) {
            for (String offender : w.ips) {
                try {
                    boolean current = offender.equals(ipKey);
                    attackGuardService.recordWeighted(offender, AttackGuardService.TYPE_TOOL,
                            "撞库分布式探测:" + accountKey, "/api/auth/login", device, "POST", false, 10,
                            current ? fingerprint : null, current ? deviceId : null,
                            current ? fingerprintSignature : null);
                } catch (Exception e) {
                    log.warn("[IronWall] credential stuffing escalation failed: {}", e.getMessage());
                }
            }
        }
        log.warn("[IronWall] credential stuffing detected: account={} ipCount={}", accountKey, w.ips.size());
    }

    private void clearAccountSpread(String loginId) {
        String accountKey = (loginId == null || loginId.isBlank()) ? "unknown" : loginId.trim();
        accountSpreadWindows.remove(accountKey);
    }

    private static class IpFailWindow {
        long windowStart = System.currentTimeMillis();
        long blockedUntil = 0;
        int count = 0;
    }

    private static class AccountSpreadWindow {
        final Set<String> ips = ConcurrentHashMap.newKeySet();
        long windowStart = System.currentTimeMillis();
        int fails = 0;
        boolean locked = false;
    }

    private static class VerifyEmailRecord {
        long windowStart = System.currentTimeMillis();
        long lastSent = 0;
        int hourCount = 0;
        long dayStart = System.currentTimeMillis();
        int dayCount = 0;
    }

    /**
     * IronWall v1.47.10: 通知设置读取。
     *
     * 1) GET 不再写库——旧实现“读不到就插入”在并发首访时会撞 user_id 唯一键，
     * 异常被吞后返回全 null，前端一律回落默认值，用户看到的开关状态是假的；
     * 2) 未初始化时直接返回与实体/数据库一致的默认值，读取路径彻底只读；
     * 3) 读取异常不再吞掉（避免把故障伪装成“设置正常”），交由全局异常处理显式失败。
     */
    public NotificationSettingsDTO getNotificationSettings(Long userId) {
        log.info("getNotificationSettings called: userId={}", userId);
        NotificationSettings settings = notificationSettingsRepository.findByUserId(userId).orElse(null);
        NotificationSettingsDTO dto = new NotificationSettingsDTO();
        dto.setEmailNotify(boolOrDefault(settings == null ? null : settings.getEmailNotify(),
                NotificationPreferenceService.DEFAULT_EMAIL_NOTIFY));
        dto.setBrowserNotify(boolOrDefault(settings == null ? null : settings.getBrowserNotify(),
                NotificationPreferenceService.DEFAULT_BROWSER_NOTIFY));
        dto.setStorageAlert(boolOrDefault(settings == null ? null : settings.getStorageAlert(),
                NotificationPreferenceService.DEFAULT_STORAGE_ALERT));
        dto.setShareNotify(boolOrDefault(settings == null ? null : settings.getShareNotify(),
                NotificationPreferenceService.DEFAULT_SHARE_NOTIFY));
        return dto;
    }

    /**
     * IronWall v1.47.10: 通知设置保存。
     *
     * 旧实现把异常吞成日志，Controller 恒返回“通知设置已更新”——数据库写失败时前端仍提示已保存。
     * 现在失败即抛出，由全局异常处理返回真实错误；写入包在事务内，避免半写。
     */
    @Transactional
    public void updateNotificationSettings(Long userId, NotificationSettingsDTO dto) {
        log.info("updateNotificationSettings called: userId={}", userId);
        NotificationSettings settings = notificationSettingsRepository.findByUserId(userId)
                .orElseGet(() -> {
                    NotificationSettings ns = new NotificationSettings();
                    ns.setUserId(userId);
                    return ns;
                });
        if (dto.getEmailNotify() != null) settings.setEmailNotify(dto.getEmailNotify());
        if (dto.getBrowserNotify() != null) settings.setBrowserNotify(dto.getBrowserNotify());
        if (dto.getStorageAlert() != null) settings.setStorageAlert(dto.getStorageAlert());
        if (dto.getShareNotify() != null) settings.setShareNotify(dto.getShareNotify());
        notificationSettingsRepository.save(settings);
    }

    private static boolean boolOrDefault(Boolean value, boolean fallback) {
        return value == null ? fallback : value;
    }

    public List<Map<String, Object>> getDevices(Long userId) {
        log.info("getDevices called: userId={}", userId);
        try {
            List<LoginHistory> histories = loginHistoryRepository
                    .findByUserIdOrderByTimeDesc(userId, org.springframework.data.domain.PageRequest.of(0, 50)).getContent();
            Map<String, Map<String, Object>> deviceMap = new LinkedHashMap<>();
            for (LoginHistory h : histories) {
                String key = h.getDevice() != null ? h.getDevice() : "Unknown";
                if (!deviceMap.containsKey(key)) {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("id", h.getId());
                    m.put("device", key);
                    m.put("ip", h.getIp());
                    m.put("lastLogin", h.getTime() != null ? h.getTime().toString() : "");
                    deviceMap.put(key, m);
                }
            }
            return new ArrayList<>(deviceMap.values());
        } catch (Exception e) {
            log.error("getDevices failed: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    public void revokeDevice(Long userId, Long historyId) {
        log.info("revokeDevice called: userId={}, historyId={}", userId, historyId);
        LoginHistory history = loginHistoryRepository.findById(historyId)
                .orElseThrow(() -> new BusinessException(ErrorCode.NOT_FOUND));
        if (!history.getUserId().equals(userId)) {
            throw new BusinessException(ErrorCode.FORBIDDEN);
        }
        loginHistoryRepository.delete(history);
    }

    // IronWall v1.28.0: 异地登录提醒去重（同一 IP 24 小时内只提醒一次）
    private static final class AlertKey {
        final String ip;
        final long at;
        AlertKey(String ip, long at) { this.ip = ip; this.at = at; }
    }
    private final Map<Long, AlertKey> lastNewLocationAlerts = new ConcurrentHashMap<>();

    /** 异地登录提醒：与上次成功登录 IP 不同时发邮件告知用户。 */
    private void sendNewLocationAlertIfNeeded(User user, String ip, String device) {
        try {
            if (user.getEmail() == null || user.getEmail().isBlank()) return;
            String prevIp = null;
            try {
                Page<LoginHistory> recent = loginHistoryRepository
                        .findByUserIdOrderByTimeDesc(user.getId(), PageRequest.of(0, 2));
                java.util.List<LoginHistory> content = recent.getContent();
                if (content.size() >= 2) {
                    String lastIp = content.get(1).getIp();
                    if (lastIp != null && !lastIp.equals(ip)) {
                        prevIp = lastIp;
                    }
                }
            } catch (Exception e) {
                return; // 历史不可读时不打扰用户
            }
            if (prevIp == null) return;
            AlertKey prev = lastNewLocationAlerts.get(user.getId());
            if (prev != null && prev.ip.equals(ip) && System.currentTimeMillis() - prev.at < 24 * 3600_000L) {
                return;
            }
            lastNewLocationAlerts.put(user.getId(), new AlertKey(ip, System.currentTimeMillis()));
            String time = LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            String deviceInfo = describeDevice(device);
            String location = "";
            try {
                Map<String, Object> geo = threatIntelService.lookupGeo(ip);
                if (geo != null && geo.get("display") != null && !geo.get("display").toString().isBlank()) {
                    location = geo.get("display").toString();
                }
            } catch (Exception e) {
                log.warn("[IronWall] login-alert geo lookup failed: {}", e.getMessage());
            }
            String subject = "【经典云网盘】新设备/异地登录提醒";
            String html = "<div style=\"font-family:'Microsoft YaHei',Arial,sans-serif;max-width:560px;margin:0 auto;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;\">"
                    + "<div style=\"background:linear-gradient(135deg,#4f46e5,#7c3aed);padding:22px 26px;\"><div style=\"color:#fff;font-size:17px;font-weight:700;\">经典云网盘官方 · 安全提醒</div></div>"
                    + "<div style=\"padding:22px 26px;color:#374151;font-size:14px;line-height:1.9;\">"
                    + "<p style=\"margin:0 0 14px;\">您好，您的经典云网盘账号刚刚在<b>新的 IP 地址</b>登录：</p>"
                    + "<table style=\"width:100%;border-collapse:collapse;font-size:13px;\">"
                    + "<tr><td style=\"padding:8px 10px;background:#f3f4f6;color:#6b7280;\">登录时间</td><td style=\"padding:8px 10px;\">" + time + "</td></tr>"
                    + "<tr><td style=\"padding:8px 10px;background:#f3f4f6;color:#6b7280;\">登录 IP</td><td style=\"padding:8px 10px;\">" + escapeHtml(ip) + "</td></tr>"
                    + (location.isEmpty() ? "" : "<tr><td style=\"padding:8px 10px;background:#f3f4f6;color:#6b7280;\">登录位置</td><td style=\"padding:8px 10px;\">" + escapeHtml(location) + "</td></tr>")
                    + "<tr><td style=\"padding:8px 10px;background:#f3f4f6;color:#6b7280;\">设备信息</td><td style=\"padding:8px 10px;\">" + escapeHtml(deviceInfo) + "</td></tr>"
                    + "</table>"
                    + "<p style=\"margin:16px 0 0;color:#b91c1c;\">如果这不是您本人的操作，请立即修改密码，并在安全中心启用两步验证。</p>"
                    + "</div>"
                    + "<div style=\"padding:14px 26px;background:#f9fafb;color:#9ca3af;font-size:12px;\">本邮件由经典云网盘安全系统自动发送，请勿直接回复。</div></div>";
            emailService.sendHtml(user.getEmail(), subject, html, "您的经典云网盘账号于 " + time + " 在 IP " + ip + "（设备：" + deviceInfo + "）登录，如非本人操作请立即修改密码。");
        } catch (Exception e) {
            log.warn("[IronWall] new-location alert failed: {}", e.getMessage());
        }
    }

    /** IronWall v1.28.6: 原始 User-Agent -> 友好设备描述（系统 · 浏览器 · 端型）。 */
    private String describeDevice(String ua) {
        if (ua == null || ua.isBlank()) return "未知设备";
        String l = ua.toLowerCase(Locale.ROOT);
        String os;
        if (l.contains("android")) {
            Matcher m = Pattern.compile("android\\s+([0-9][0-9.]*)").matcher(ua);
            os = m.find() ? "Android " + m.group(1) : "Android";
        } else if (l.contains("iphone") || l.contains("ipod")) {
            os = "iOS (iPhone)";
        } else if (l.contains("ipad")) {
            os = "iOS (iPad)";
        } else if (l.contains("windows nt 10")) {
            os = "Windows 10/11";
        } else if (l.contains("windows")) {
            os = "Windows";
        } else if (l.contains("mac os x") || l.contains("macintosh")) {
            os = "macOS";
        } else if (l.contains("linux")) {
            os = "Linux";
        } else {
            os = "未知系统";
        }
        String browser;
        if (l.contains("micromessenger")) {
            browser = "微信内置浏览器";
        } else if (l.contains("edg/")) {
            Matcher m = Pattern.compile("edg/([0-9][0-9.]*)").matcher(ua);
            browser = m.find() ? "Edge " + m.group(1) : "Edge";
        } else if (l.contains("mqqbrowser")) {
            browser = "QQ浏览器";
        } else if (l.contains("opr/") || l.contains("opera")) {
            browser = "Opera";
        } else if (l.contains("firefox/")) {
            Matcher m = Pattern.compile("firefox/([0-9][0-9.]*)").matcher(ua);
            browser = m.find() ? "Firefox " + m.group(1) : "Firefox";
        } else if (l.contains("chrome/")) {
            Matcher m = Pattern.compile("chrome/([0-9][0-9.]*)").matcher(ua);
            browser = m.find() ? "Chrome " + m.group(1) : "Chrome";
        } else if (l.contains("safari/")) {
            browser = "Safari";
        } else {
            browser = "未知浏览器";
        }
        String kind = l.contains("mobile") || l.contains("android") || l.contains("iphone") || l.contains("ipad") ? "移动端" : "桌面端";
        return os + " · " + browser + " · " + kind;
    }

    private String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private LoginResponse buildLoginResponse(User user, String token, LocalDateTime expiresAt) {
        LoginResponse response = new LoginResponse();
        response.setToken(token);
        if (expiresAt != null) {
            response.setExpiresAt(expiresAt.toString());
        }
        LoginResponse.UserInfo info = new LoginResponse.UserInfo();
        info.setId(user.getId());
        info.setUsername(user.getUsername());
        info.setEmail(user.getEmail());
        info.setRole(user.getRole());
        info.setOfficial(user.getIsOfficial() != null && user.getIsOfficial());
        info.setUserStatus(user.getUserStatus());
        info.setVerificationStatus(user.getVerificationStatus());
        info.setStorageUsed(user.getStorageUsed());
        info.setStorageLimit(user.getStorageLimit());
        info.setUploadLimit(user.getUploadLimit());
        info.setCreatedAt(user.getCreatedAt() != null ? user.getCreatedAt().toString() : null);
        info.setAvatar(user.getAvatar());
        info.setUserCode(user.getUserCode());
        info.setVerificationBadge(user.getVerificationBadge());
        response.setUser(info);
        return response;
    }
}
