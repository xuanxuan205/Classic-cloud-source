package com.jdy.cloud.service;

import com.jdy.cloud.dto.LoginRequest;
import com.jdy.cloud.dto.LoginResponse;
import com.jdy.cloud.dto.NotificationSettingsDTO;
import com.jdy.cloud.dto.RegisterRequest;
import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.ErrorCode;
import com.jdy.cloud.model.NotificationSettings;
import com.jdy.cloud.model.User;
import com.jdy.cloud.repository.LoginHistoryRepository;
import com.jdy.cloud.repository.NotificationSettingsRepository;
import com.jdy.cloud.repository.UserRepository;
import com.jdy.cloud.security.JwtTokenProvider;
import com.jdy.cloud.security.AttackGuardService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private JwtTokenProvider jwtTokenProvider;
    @Mock private EmailService emailService;
    @Mock private LoginHistoryRepository loginHistoryRepository;
    @Mock private VerificationCodeService verificationCodeService;
    @Mock private AuditLogService auditLogService;
    @Mock private TotpService totpService;
    @Mock private AttackGuardService attackGuardService;
    @Mock private NotificationSettingsRepository notificationSettingsRepository;

    @InjectMocks
    private AuthService authService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("testuser");
        testUser.setEmail("test@example.com");
        testUser.setPassword("encoded_password");
        testUser.setRole("user");
        testUser.setLoginAttempts(0);
    }

    @Test
    void login_shouldReturnToken_whenCredentialsAreValid() {
        LoginRequest request = new LoginRequest();
        request.setUsername("testuser");
        request.setPassword("correct");

        when(userRepository.findByLoginId("testuser")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("correct", "encoded_password")).thenReturn(true);
        when(jwtTokenProvider.generateToken(eq(1L), eq("testuser"), eq("user"), eq(false), anyInt())).thenReturn("jwt-token");
        when(jwtTokenProvider.getExpirationMs()).thenReturn(86400000L);

        LoginResponse response = authService.login(request, "127.0.0.1", "test-agent");

        assertNotNull(response.getToken());
        assertEquals("jwt-token", response.getToken());
        assertEquals(testUser.getId(), response.getUser().getId());
        verify(loginHistoryRepository).save(any());
    }

    @Test
    void login_shouldThrow_whenUserNotFound() {
        LoginRequest request = new LoginRequest();
        request.setUsername("nobody");
        request.setPassword("any");

        when(userRepository.findByLoginId("nobody")).thenReturn(Optional.empty());

        BusinessException ex = assertThrows(BusinessException.class,
                () -> authService.login(request, "127.0.0.1", "agent"));
        assertEquals(ErrorCode.WRONG_PASSWORD.getCode(), ex.getCode());
    }

    @Test
    void login_shouldThrow_whenPasswordIsWrong() {
        LoginRequest request = new LoginRequest();
        request.setUsername("testuser");
        request.setPassword("wrong");

        when(userRepository.findByLoginId("testuser")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("wrong", "encoded_password")).thenReturn(false);

        BusinessException ex = assertThrows(BusinessException.class,
                () -> authService.login(request, "127.0.0.1", "agent"));
        assertEquals(ErrorCode.WRONG_PASSWORD.getCode(), ex.getCode());
        assertEquals(1, testUser.getLoginAttempts());
    }

    @Test
    void login_shouldThrow_whenAccountIsLocked() {
        testUser.setLockedUntil(LocalDateTime.now().plusMinutes(10));
        LoginRequest request = new LoginRequest();
        request.setUsername("testuser");
        request.setPassword("any");

        when(userRepository.findByLoginId("testuser")).thenReturn(Optional.of(testUser));

        BusinessException ex = assertThrows(BusinessException.class,
                () -> authService.login(request, "127.0.0.1", "agent"));
        assertEquals(ErrorCode.WRONG_PASSWORD.getCode(), ex.getCode());
    }

    @Test
    void login_shouldLockAccount_afterFiveFailedAttempts() {
        testUser.setLoginAttempts(4);
        LoginRequest request = new LoginRequest();
        request.setUsername("testuser");
        request.setPassword("wrong");

        when(userRepository.findByLoginId("testuser")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("wrong", "encoded_password")).thenReturn(false);

        assertThrows(BusinessException.class,
                () -> authService.login(request, "127.0.0.1", "agent"));
        assertEquals(5, testUser.getLoginAttempts());
        assertNotNull(testUser.getLockedUntil());
    }

    @Test
    void register_shouldThrow_whenUsernameExists() {
        RegisterRequest request = new RegisterRequest();
        request.setUsername("testuser");
        request.setEmail("new@example.com");
        request.setPassword("Str0ng!Pass");
        request.setCode("123456");

        when(userRepository.existsByUsername("testuser")).thenReturn(true);

        BusinessException ex = assertThrows(BusinessException.class,
                () -> authService.register(request));
        assertEquals(ErrorCode.USERNAME_EXISTS.getCode(), ex.getCode());
    }

    @Test
    void register_shouldThrow_whenEmailExists() {
        RegisterRequest request = new RegisterRequest();
        request.setUsername("newuser");
        request.setEmail("test@example.com");
        request.setPassword("Str0ng!Pass");
        request.setCode("123456");

        when(userRepository.existsByUsername("newuser")).thenReturn(false);
        when(userRepository.existsByEmail("test@example.com")).thenReturn(true);

        BusinessException ex = assertThrows(BusinessException.class,
                () -> authService.register(request));
        assertEquals(ErrorCode.EMAIL_EXISTS.getCode(), ex.getCode());
    }

    @Test
    void register_shouldVerifyCodeBeforeUsernameCheck() {
        RegisterRequest request = new RegisterRequest();
        request.setUsername("testuser");
        request.setEmail("new@example.com");
        request.setPassword("Str0ng!Pass");
        request.setCode("123456");

        doThrow(new BusinessException(ErrorCode.CODE_ERROR)).when(verificationCodeService).verify("new@example.com", "123456");

        BusinessException ex = assertThrows(BusinessException.class,
                () -> authService.register(request));
        assertEquals(ErrorCode.CODE_ERROR.getCode(), ex.getCode());
        verify(userRepository, never()).existsByUsername(anyString());
    }

    @Test
    void login_shouldBlockIp_afterTenFailures() {
        LoginRequest request = new LoginRequest();
        request.setUsername("testuser");
        request.setPassword("wrong");

        when(userRepository.findByLoginId("testuser")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("wrong", "encoded_password")).thenReturn(false);

        for (int i = 0; i < 9; i++) {
            assertThrows(BusinessException.class,
                    () -> authService.login(request, "203.0.113.9", "agent"));
        }
        BusinessException ex = assertThrows(BusinessException.class,
                () -> authService.login(request, "203.0.113.9", "agent"));
        assertEquals(ErrorCode.TOO_MANY_REQUESTS.getCode(), ex.getCode());
    }

    @Test
    void login_shouldNotBlockOtherIp() {
        LoginRequest request = new LoginRequest();
        request.setUsername("testuser");
        request.setPassword("wrong");

        when(userRepository.findByLoginId("testuser")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("wrong", "encoded_password")).thenReturn(false);

        for (int i = 0; i < 10; i++) {
            try {
                authService.login(request, "203.0.113.9", "agent");
            } catch (BusinessException ignored) { }
        }
        BusinessException ex = assertThrows(BusinessException.class,
                () -> authService.login(request, "203.0.113.10", "agent"));
        assertEquals(ErrorCode.WRONG_PASSWORD.getCode(), ex.getCode());
    }

    @Test
    void login_shouldNotBlockOtherUser_sameIp() {
        LoginRequest rA = new LoginRequest();
        rA.setUsername("userA");
        rA.setPassword("wrong");
        when(userRepository.findByLoginId("userA")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("wrong", "encoded_password")).thenReturn(false);
        for (int i = 0; i < 10; i++) {
            try { authService.login(rA, "203.0.113.9", "agent"); } catch (BusinessException ignored) { }
        }

        LoginRequest rB = new LoginRequest();
        rB.setUsername("userB");
        rB.setPassword("wrong");
        when(userRepository.findByLoginId("userB")).thenReturn(Optional.empty());

        BusinessException ex = assertThrows(BusinessException.class,
                () -> authService.login(rB, "203.0.113.9", "agent"));
        assertEquals(ErrorCode.WRONG_PASSWORD.getCode(), ex.getCode());
    }

    @Test
    void login_shouldAllowCorrectPassword_afterPairFailures() {
        LoginRequest wrong = new LoginRequest();
        wrong.setUsername("testuser");
        wrong.setPassword("wrong");
        when(userRepository.findByLoginId("testuser")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("wrong", "encoded_password")).thenReturn(false);
        for (int i = 0; i < 9; i++) {
            assertThrows(BusinessException.class, () -> authService.login(wrong, "203.0.113.9", "agent"));
        }
        assertThrows(BusinessException.class, () -> authService.login(wrong, "203.0.113.9", "agent"));

        // 同 IP 下另一账号 + 正确密码：不应被他人失败冷却连坐
        User other = new User();
        other.setId(2L);
        other.setUsername("userB");
        other.setEmail("b@example.com");
        other.setPassword("encodedB");
        other.setRole("user");
        other.setLoginAttempts(0);

        LoginRequest ok = new LoginRequest();
        ok.setUsername("userB");
        ok.setPassword("right");
        when(userRepository.findByLoginId("userB")).thenReturn(Optional.of(other));
        when(passwordEncoder.matches("right", "encodedB")).thenReturn(true);
        when(jwtTokenProvider.generateToken(anyLong(), anyString(), anyString(), anyBoolean(), anyInt())).thenReturn("token123");
        when(jwtTokenProvider.getExpirationMs()).thenReturn(86400000L);

        LoginResponse resp = authService.login(ok, "203.0.113.9", "agent");
        assertNotNull(resp);
        assertEquals("token123", resp.getToken());
    }

    @Test
    void login_shouldBlockIpGlobally_afterThirtyFailures() {
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);
        for (int i = 0; i < 29; i++) {
            LoginRequest r = new LoginRequest();
            r.setUsername("spray" + i);
            r.setPassword("wrong");
            assertThrows(BusinessException.class, () -> authService.login(r, "203.0.113.9", "agent"));
        }
        LoginRequest r30 = new LoginRequest();
        r30.setUsername("spray29");
        r30.setPassword("wrong");
        BusinessException ex = assertThrows(BusinessException.class,
                () -> authService.login(r30, "203.0.113.9", "agent"));
        assertEquals(ErrorCode.TOO_MANY_REQUESTS.getCode(), ex.getCode());
    }

    @Test
    void verifyEmail_shouldLimitPerIp() {
        User userA = new User();
        userA.setId(1L);
        userA.setEmail("a@example.com");
        User userB = new User();
        userB.setId(2L);
        userB.setEmail("b@example.com");

        when(userRepository.findById(1L)).thenReturn(Optional.of(userA));
        when(userRepository.findById(2L)).thenReturn(Optional.of(userB));

        authService.sendVerificationEmail(1L, "203.0.113.5");
        BusinessException ex = assertThrows(BusinessException.class,
                () -> authService.sendVerificationEmail(2L, "203.0.113.5"));
        assertEquals(ErrorCode.CODE_TOO_FREQUENT.getCode(), ex.getCode());
        verify(verificationCodeService, times(1)).sendCode(anyString(), anyString());
    }

    @Test
    void verifyEmail_shouldEnforceDailyQuotaPerUser() {
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));

        java.util.Map<?, ?> records = (java.util.Map<?, ?>) ReflectionTestUtils.getField(AuthService.class, "VERIFY_EMAIL_RECORDS");
        ((java.util.Map<Object, Object>) records).remove(1L);

        authService.sendVerificationEmail(1L, "198.51.100.7");
        verify(verificationCodeService, times(1)).sendCode(anyString(), anyString());

        Object rec = records.get(1L);
        assertNotNull(rec);
        ReflectionTestUtils.setField(rec, "lastSent", 0L);
        ReflectionTestUtils.setField(rec, "hourCount", 0);
        ReflectionTestUtils.setField(rec, "dayCount", 10);

        BusinessException ex = assertThrows(BusinessException.class,
                () -> authService.sendVerificationEmail(1L, "198.51.100.8"));
        assertEquals(ErrorCode.TOO_MANY_REQUESTS.getCode(), ex.getCode());
        assertTrue(ex.getMessage().contains("明天"));

        ((java.util.Map<Object, Object>) records).remove(1L);
    }

    @Test
    void uploadAvatar_shouldThrowBadRequest_whenFileIsEmpty() {
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));

        org.springframework.mock.web.MockMultipartFile empty =
                new org.springframework.mock.web.MockMultipartFile("avatar", "empty.png", "image/png", new byte[0]);

        BusinessException ex = assertThrows(BusinessException.class,
                () -> authService.uploadAvatar(1L, empty));
        assertEquals(ErrorCode.BAD_REQUEST.getCode(), ex.getCode());
    }

    @Test
    void login_shouldRejectBannedAccount_evenWithCorrectPassword() {
        testUser.setUserStatus("banned");
        LoginRequest request = new LoginRequest();
        request.setUsername("testuser");
        request.setPassword("correct");

        when(userRepository.findByLoginId("testuser")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("correct", "encoded_password")).thenReturn(true);

        BusinessException ex = assertThrows(BusinessException.class,
                () -> authService.login(request, "127.0.0.1", "agent"));
        assertEquals(ErrorCode.ACCOUNT_BANNED.getCode(), ex.getCode());
        assertEquals(0, testUser.getLoginAttempts());
        verify(loginHistoryRepository, never()).save(any());
    }

    @Test
    void uploadAvatar_shouldCountIntoQuotaAndReturnUrl() throws Exception {
        Path temp = Files.createTempDirectory("avatar-quota-test");
        try {
            ReflectionTestUtils.setField(authService, "uploadDir", temp.toString());
            testUser.setAvatarSize(0L);
            testUser.setAvatar(null);
            byte[] png = new byte[]{(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4, 5, 6, 7, 8};
            org.springframework.mock.web.MockMultipartFile file =
                    new org.springframework.mock.web.MockMultipartFile("avatar", "a.png", "image/png", png);

            when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
            when(userRepository.incrementStorageUsedWithinLimit(eq(1L), anyLong())).thenReturn(1);
            when(userRepository.updateAvatar(eq(1L), contains("/api/files/avatar/"), anyLong())).thenReturn(1);

            String url = authService.uploadAvatar(1L, file);

            assertNotNull(url);
            assertTrue(url.startsWith("/api/files/avatar/"));
            verify(userRepository).incrementStorageUsedWithinLimit(eq(1L), anyLong());
            verify(userRepository).updateAvatar(eq(1L), anyString(), anyLong());
        } finally {
            if (Files.exists(temp)) {
                Files.walk(temp).sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    @Test
    void uploadAvatar_shouldThrowStorageFullAndDeleteWrittenFile() throws Exception {
        Path temp = Files.createTempDirectory("avatar-full-test");
        try {
            ReflectionTestUtils.setField(authService, "uploadDir", temp.toString());
            testUser.setAvatarSize(0L);
            testUser.setAvatar(null);
            byte[] png = new byte[]{(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4, 5, 6, 7, 8};
            org.springframework.mock.web.MockMultipartFile file =
                    new org.springframework.mock.web.MockMultipartFile("avatar", "a.png", "image/png", png);

            when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
            when(userRepository.incrementStorageUsedWithinLimit(eq(1L), anyLong())).thenReturn(0);

            BusinessException ex = assertThrows(BusinessException.class,
                    () -> authService.uploadAvatar(1L, file));
            assertEquals(ErrorCode.STORAGE_FULL.getCode(), ex.getCode());

            Path avatarsDir = temp.resolve("avatars");
            long files = Files.exists(avatarsDir) ? Files.list(avatarsDir).count() : 0;
            assertEquals(0L, files);
        } finally {
            if (Files.exists(temp)) {
                Files.walk(temp).sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    @Test
    void uploadAvatar_shouldFallbackToNative_whenJpqlUpdateThrows() throws Exception {
        Path temp = Files.createTempDirectory("avatar-fallback-test");
        try {
            ReflectionTestUtils.setField(authService, "uploadDir", temp.toString());
            testUser.setAvatarSize(0L);
            testUser.setAvatar(null);
            byte[] png = new byte[]{(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4, 5, 6, 7, 8};
            org.springframework.mock.web.MockMultipartFile file =
                    new org.springframework.mock.web.MockMultipartFile("avatar", "a.png", "image/png", png);

            when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
            when(userRepository.incrementStorageUsedWithinLimit(eq(1L), anyLong())).thenReturn(1);
            when(userRepository.updateAvatar(eq(1L), contains("/api/files/avatar/"), anyLong()))
                    .thenThrow(new RuntimeException("unknown column avatar_size"));
            when(userRepository.updateAvatarNative(eq(1L), contains("/api/files/avatar/"), anyLong())).thenReturn(1);

            String url = authService.uploadAvatar(1L, file);

            assertNotNull(url);
            assertTrue(url.startsWith("/api/files/avatar/"));
            verify(userRepository).updateAvatarNative(eq(1L), contains("/api/files/avatar/"), anyLong());
        } finally {
            if (Files.exists(temp)) {
                Files.walk(temp).sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    @Test
    void uploadAvatar_shouldFallbackToUrlOnly_whenAvatarSizeColumnUnavailable() throws Exception {
        Path temp = Files.createTempDirectory("avatar-urlonly-test");
        try {
            ReflectionTestUtils.setField(authService, "uploadDir", temp.toString());
            testUser.setAvatarSize(0L);
            testUser.setAvatar(null);
            byte[] png = new byte[]{(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4, 5, 6, 7, 8};
            org.springframework.mock.web.MockMultipartFile file =
                    new org.springframework.mock.web.MockMultipartFile("avatar", "a.png", "image/png", png);

            when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
            when(userRepository.incrementStorageUsedWithinLimit(eq(1L), anyLong())).thenReturn(1);
            when(userRepository.updateAvatar(eq(1L), contains("/api/files/avatar/"), anyLong()))
                    .thenThrow(new RuntimeException("unknown column avatar_size"));
            when(userRepository.updateAvatarNative(eq(1L), contains("/api/files/avatar/"), anyLong()))
                    .thenThrow(new RuntimeException("unknown column avatar_size"));
            when(userRepository.updateAvatarUrlOnly(eq(1L), contains("/api/files/avatar/"))).thenReturn(1);

            String url = authService.uploadAvatar(1L, file);

            assertNotNull(url);
            assertTrue(url.startsWith("/api/files/avatar/"));
            verify(userRepository).updateAvatarUrlOnly(eq(1L), contains("/api/files/avatar/"));
        } finally {
            if (Files.exists(temp)) {
                Files.walk(temp).sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    // ========== IronWall v1.29.0: 账号三维联动（账号/设备/IP） ==========

    @Test
    void deviceBruteForce_shouldEscalateToAttackGuardOnce() {
        String deviceId = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "."
                + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        String fingerprint = "cccc0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff";
        when(userRepository.findByLoginId(anyString())).thenReturn(Optional.empty());

        for (int i = 0; i < 10; i++) {
            LoginRequest request = new LoginRequest();
            request.setUsername("victim" + i);
            request.setPassword("wrong");
            assertThrows(BusinessException.class, () -> authService.login(
                    request, "203.0.113.200", "agent", fingerprint, deviceId, "sig"));
        }

        verify(attackGuardService, times(1)).recordWeighted(
                eq("203.0.113.200"), eq(AttackGuardService.TYPE_TOOL), contains("设备登录爆破"),
                eq("/api/auth/login"), eq("agent"), eq("POST"), eq(false), eq(10),
                eq(fingerprint), eq(deviceId), eq("sig"));
    }

    @Test
    void accountSpread_shouldLockAccountAndScoreAllOffenderIps() {
        when(userRepository.findByLoginId("spread-target")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("wrong", "encoded_password")).thenReturn(false);

        String[] ips = {"203.0.113.210", "203.0.113.211", "203.0.113.212", "203.0.113.213"};
        for (String ip : ips) {
            LoginRequest request = new LoginRequest();
            request.setUsername("spread-target");
            request.setPassword("wrong");
            assertThrows(BusinessException.class, () -> authService.login(request, ip, "agent"));
        }

        assertNotNull(testUser.getLockedUntil(), "跨IP撞库应锁定账号");
        assertTrue(testUser.getLockedUntil().isAfter(LocalDateTime.now()));
        verify(userRepository, atLeast(1)).save(testUser);
        verify(attackGuardService, times(4)).recordWeighted(
                anyString(), eq(AttackGuardService.TYPE_TOOL), contains("撞库分布式探测"),
                eq("/api/auth/login"), eq("agent"), eq("POST"), eq(false), eq(10),
                nullable(String.class), nullable(String.class), nullable(String.class));
    }

    @Test
    void loginSuccess_shouldClearDeviceAndAccountDimensions() {
        String deviceId = "dddddddddddddddddddddddddddddddd" + "."
                + "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        when(userRepository.findByLoginId("spread-target")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("wrong", "encoded_password")).thenReturn(false);

        for (int i = 0; i < 3; i++) {
            LoginRequest request = new LoginRequest();
            request.setUsername("spread-target");
            request.setPassword("wrong");
            assertThrows(BusinessException.class, () -> authService.login(
                    request, "203.0.113.220", "agent", null, deviceId, null));
        }

        @SuppressWarnings("unchecked")
        java.util.Map<String, ?> deviceWindows =
                (java.util.Map<String, ?>) ReflectionTestUtils.getField(authService, "deviceFailWindows");
        assertNotNull(deviceWindows);
        assertFalse(deviceWindows.isEmpty(), "登录成功前设备维失败窗口应有记录");

        when(passwordEncoder.matches("correct", "encoded_password")).thenReturn(true);
        when(jwtTokenProvider.generateToken(eq(1L), eq("testuser"), eq("user"), eq(false), anyInt()))
                .thenReturn("jwt-token");
        when(jwtTokenProvider.getExpirationMs()).thenReturn(86400000L);

        LoginRequest ok = new LoginRequest();
        ok.setUsername("spread-target");
        ok.setPassword("correct");
        authService.login(ok, "203.0.113.220", "agent", null, deviceId, null);

        assertTrue(deviceWindows.isEmpty(), "登录成功应清空该设备的失败窗口（防误封）");
    }

    /** IronWall v1.47.10: GET 未初始化时返回默认值且绝不写库（消除并发唯一键竞态）。 */
    @Test
    void getNotificationSettings_shouldReturnDefaultsWithoutInsertingRow() {
        when(notificationSettingsRepository.findByUserId(1L)).thenReturn(Optional.empty());

        NotificationSettingsDTO dto = authService.getNotificationSettings(1L);

        assertEquals(Boolean.TRUE, dto.getEmailNotify());
        assertEquals(Boolean.TRUE, dto.getBrowserNotify());
        assertEquals(Boolean.TRUE, dto.getStorageAlert());
        assertEquals(Boolean.FALSE, dto.getShareNotify());
        verify(notificationSettingsRepository, never()).save(any());
    }

    /** IronWall v1.47.10: GET 必须原样回读已保存的四个开关。 */
    @Test
    void getNotificationSettings_shouldReturnStoredValues() {
        NotificationSettings stored = new NotificationSettings();
        stored.setUserId(1L);
        stored.setEmailNotify(false);
        stored.setBrowserNotify(false);
        stored.setStorageAlert(false);
        stored.setShareNotify(true);
        when(notificationSettingsRepository.findByUserId(1L)).thenReturn(Optional.of(stored));

        NotificationSettingsDTO dto = authService.getNotificationSettings(1L);

        assertEquals(Boolean.FALSE, dto.getEmailNotify());
        assertEquals(Boolean.FALSE, dto.getBrowserNotify());
        assertEquals(Boolean.FALSE, dto.getStorageAlert());
        assertEquals(Boolean.TRUE, dto.getShareNotify());
    }

    /** IronWall v1.47.10: PUT 必须把四个开关原样落库。 */
    @Test
    void updateNotificationSettings_shouldPersistAllFourFlags() {
        NotificationSettings stored = new NotificationSettings();
        stored.setUserId(1L);
        when(notificationSettingsRepository.findByUserId(1L)).thenReturn(Optional.of(stored));

        NotificationSettingsDTO dto = new NotificationSettingsDTO();
        dto.setEmailNotify(false);
        dto.setBrowserNotify(true);
        dto.setStorageAlert(false);
        dto.setShareNotify(true);
        authService.updateNotificationSettings(1L, dto);

        assertFalse(stored.getEmailNotify());
        assertTrue(stored.getBrowserNotify());
        assertFalse(stored.getStorageAlert());
        assertTrue(stored.getShareNotify());
        verify(notificationSettingsRepository).save(stored);
    }

    /** IronWall v1.47.10: 首次保存自动建行，且不会因缺行而丢设置。 */
    @Test
    void updateNotificationSettings_shouldCreateRowWhenAbsent() {
        when(notificationSettingsRepository.findByUserId(1L)).thenReturn(Optional.empty());

        NotificationSettingsDTO dto = new NotificationSettingsDTO();
        dto.setShareNotify(true);
        authService.updateNotificationSettings(1L, dto);

        org.mockito.ArgumentCaptor<NotificationSettings> captor =
                org.mockito.ArgumentCaptor.forClass(NotificationSettings.class);
        verify(notificationSettingsRepository).save(captor.capture());
        assertEquals(1L, captor.getValue().getUserId());
        assertTrue(captor.getValue().getShareNotify());
    }

    /** IronWall v1.47.10: 保存失败必须抛出，不能静默假装成功。 */
    @Test
    void updateNotificationSettings_shouldPropagateFailure() {
        when(notificationSettingsRepository.findByUserId(1L))
                .thenThrow(new org.springframework.dao.DataAccessResourceFailureException("db down"));

        NotificationSettingsDTO dto = new NotificationSettingsDTO();
        dto.setEmailNotify(true);

        assertThrows(org.springframework.dao.DataAccessResourceFailureException.class,
                () -> authService.updateNotificationSettings(1L, dto));
        verify(notificationSettingsRepository, never()).save(any());
    }
}
