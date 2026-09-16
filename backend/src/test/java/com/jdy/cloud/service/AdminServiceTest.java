package com.jdy.cloud.service;

import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.ErrorCode;
import com.jdy.cloud.dto.UpdateUserRequest;
import com.jdy.cloud.model.FileEntity;
import com.jdy.cloud.model.Share;
import com.jdy.cloud.model.User;
import com.jdy.cloud.repository.AnnouncementRepository;
import com.jdy.cloud.repository.FileRepository;
import com.jdy.cloud.repository.FolderRepository;
import com.jdy.cloud.repository.LoginHistoryRepository;
import com.jdy.cloud.repository.ShareRepository;
import com.jdy.cloud.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/** IronWall v1.47.0: 管理员删除文件一致性（硬删除 + 分享失效 + 列表排除 + 孤儿清理）。 */
@ExtendWith(MockitoExtension.class)
class AdminServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private FileRepository fileRepository;
    @Mock private ShareRepository shareRepository;
    @Mock private AnnouncementRepository announcementRepository;
    @Mock private FolderRepository folderRepository;
    @Mock private LoginHistoryRepository loginHistoryRepository;
    @Mock private com.jdy.cloud.security.TokenVersionService tokenVersionService;
    @Mock private EmailService emailService;
    @Mock private AuditLogService auditLogService;
    @Mock private NotificationPreferenceService notificationPreferenceService;

    @InjectMocks
    private AdminService adminService;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() throws Exception {
        var field = AdminService.class.getDeclaredField("uploadDir");
        field.setAccessible(true);
        field.set(adminService, tempDir.toString());
        // IronWall v1.47.10: 默认放行通知邮件，门控用例单独覆盖
        lenient().when(notificationPreferenceService.emailNotifyEnabled(any())).thenReturn(true);
        lenient().when(notificationPreferenceService.shouldEmailShareNotify(any())).thenReturn(true);
    }

    private FileEntity file(Long id, Long userId, String storedName, String originalName, long size, int status) {
        FileEntity f = new FileEntity();
        f.setId(id);
        f.setUserId(userId);
        f.setFilename(storedName);
        f.setOriginalName(originalName);
        f.setFileSize(size);
        f.setStatus(status);
        return f;
    }

    @Test
    void getFiles_shouldExcludeDeletedStatus() {
        Page<FileEntity> page = new PageImpl<>(List.of(file(1L, 2L, "a.txt", "a.txt", 10L, 1)));
        when(fileRepository.findByStatusNot(eq(-1), any(PageRequest.class))).thenReturn(page);

        Page<FileEntity> result = adminService.getFiles(0, 20);

        assertEquals(1, result.getTotalElements());
        verify(fileRepository).findByStatusNot(eq(-1), any(PageRequest.class));
        verify(fileRepository, never()).findAll(any(PageRequest.class));
    }

    @Test
    void updateFileStatus_shouldRejectInvalidStatus() {
        BusinessException ex = assertThrows(BusinessException.class,
                () -> adminService.updateFileStatus(1L, 5));
        assertEquals(ErrorCode.BAD_REQUEST.getCode(), ex.getCode());
        verify(fileRepository, never()).findById(any());
    }

    @Test
    void updateFileStatus_minusOne_shouldHardDeleteEverything() throws Exception {
        FileEntity f = file(9L, 7L, "stored.bin", "报告.pdf", 100L, 1);
        when(fileRepository.findById(9L)).thenReturn(Optional.of(f));
        when(fileRepository.countByFilename("stored.bin")).thenReturn(0L);
        Files.write(tempDir.resolve("stored.bin"), new byte[]{1, 2, 3});

        adminService.updateFileStatus(9L, -1);

        verify(shareRepository).deleteByFileId(9L);
        verify(fileRepository).delete(f);
        assertFalse(Files.exists(tempDir.resolve("stored.bin")), "物理文件应被删除");
        verify(userRepository).incrementStorageUsed(7L, -100L);
        verify(auditLogService).logDeleteFile(7L, "报告.pdf", "admin", true);
    }

    @Test
    void updateFileStatus_minusOne_shouldKeepPhysicalFile_whenDedupReferencesExist() throws Exception {
        FileEntity f = file(9L, 7L, "shared.bin", "dup.pdf", 50L, 0);
        when(fileRepository.findById(9L)).thenReturn(Optional.of(f));
        when(fileRepository.countByFilename("shared.bin")).thenReturn(2L);
        Files.write(tempDir.resolve("shared.bin"), new byte[]{1});

        adminService.updateFileStatus(9L, -1);

        assertTrue(Files.exists(tempDir.resolve("shared.bin")), "秒传去重：仍被引用时不得删除物理文件");
        verify(fileRepository).delete(f);
    }

    @Test
    void updateFileStatus_zero_shouldBanAndAudit() {
        FileEntity f = file(3L, 7L, "s.bin", "违规文件.txt", 10L, 1);
        when(fileRepository.findById(3L)).thenReturn(Optional.of(f));

        adminService.updateFileStatus(3L, 0);

        assertEquals(0, f.getStatus());
        verify(fileRepository).save(f);
        verify(auditLogService).logAdminAction(eq(0L), eq("file-ban"), eq("file"), eq("3"), anyString(), anyString());
    }

    @Test
    void purgeLegacyDeletedFiles_shouldHardDeleteOrphans() throws Exception {
        FileEntity legacy = file(42L, 7L, "legacy.bin", "旧文件.txt", 30L, -1);
        when(fileRepository.findByStatus(-1)).thenReturn(List.of(legacy));
        when(fileRepository.countByFilename("legacy.bin")).thenReturn(0L);
        Files.write(tempDir.resolve("legacy.bin"), new byte[]{1});

        adminService.purgeLegacyDeletedFiles();

        verify(shareRepository).deleteByFileId(42L);
        verify(fileRepository).delete(legacy);
        assertFalse(Files.exists(tempDir.resolve("legacy.bin")));
        verify(userRepository).incrementStorageUsed(7L, -30L);
    }

    @Test
    void getDashboardStats_shouldIncludeStorageActivityAndShareCounts() {
        when(userRepository.count()).thenReturn(5L);
        when(userRepository.countByUserStatus("active")).thenReturn(4L);
        when(fileRepository.countByStatusNot(-1)).thenReturn(12L);
        when(fileRepository.countByCreatedAtAfter(any(LocalDateTime.class))).thenReturn(3L);
        when(shareRepository.count()).thenReturn(7L);
        when(shareRepository.countByCreatedAtAfter(any(LocalDateTime.class))).thenReturn(2L);
        when(userRepository.sumStorageUsed()).thenReturn(1000L);
        when(userRepository.sumStorageLimit()).thenReturn(5000L);

        Map<String, Object> stats = adminService.getDashboardStats();

        assertEquals(5L, stats.get("totalUsers"));
        assertEquals(4L, stats.get("activeUsers"));
        assertEquals(12L, stats.get("totalFiles"));
        assertEquals(3L, stats.get("todayUploads"));
        assertEquals(7L, stats.get("totalShares"));
        assertEquals(2L, stats.get("todayShares"));
        assertEquals(1000L, stats.get("storageUsed"));
        assertEquals(5000L, stats.get("storageTotal"));
        assertEquals(4000L, stats.get("storageRemaining"));
    }

    @Test
    void getDashboardStats_shouldClampRemainingAtZero_whenOverQuota() {
        when(userRepository.sumStorageUsed()).thenReturn(6000L);
        when(userRepository.sumStorageLimit()).thenReturn(5000L);

        Map<String, Object> stats = adminService.getDashboardStats();

        assertEquals(0L, stats.get("storageRemaining"));
    }

    @Test
    void getUsers_withKeyword_shouldUseRepositorySearch() {
        when(userRepository.searchByKeyword(eq("alice"), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of()));

        adminService.getUsers(0, 20, "alice");

        verify(userRepository).searchByKeyword(eq("alice"), any(PageRequest.class));
        verify(userRepository, never()).findAll(any(PageRequest.class));
    }

    @Test
    void getUsers_blankKeyword_shouldFallbackToFindAll() {
        when(userRepository.findAll(any(PageRequest.class))).thenReturn(new PageImpl<>(List.of()));

        adminService.getUsers(0, 20, "   ");

        verify(userRepository).findAll(any(PageRequest.class));
        verify(userRepository, never()).searchByKeyword(anyString(), any(PageRequest.class));
    }

    @Test
    void getShares_keywordWithoutMatchingUsers_shouldSearchShareCodeOnly() {
        when(userRepository.findIdsByKeyword("abc")).thenReturn(List.of());
        when(shareRepository.findByShareCodeContainingIgnoreCase(eq("abc"), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of()));

        adminService.getShares(0, 20, "abc");

        verify(shareRepository).findByShareCodeContainingIgnoreCase(eq("abc"), any(PageRequest.class));
        verify(shareRepository, never()).findAll(any(PageRequest.class));
    }

    @Test
    void getFiles_keywordWithMatchingUsers_shouldSearchByNameOrUserIds() {
        when(userRepository.findIdsByKeyword("alice")).thenReturn(List.of(7L));
        when(fileRepository.searchByKeywordOrUserIds(eq("alice"), eq(List.of(7L)), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of()));

        adminService.getFiles(0, 20, "alice");

        verify(fileRepository).searchByKeywordOrUserIds(eq("alice"), eq(List.of(7L)), any(PageRequest.class));
        verify(fileRepository, never()).findByStatusNot(anyInt(), any(PageRequest.class));
    }

    /** IronWall v1.47.10: 关闭“分享通知”后，分享封禁不再发信。 */
    @Test
    void updateShareStatus_shouldSkipShareMailWhenPreferenceOff() {
        when(shareRepository.findById(5L)).thenReturn(Optional.of(share(5L, 7L, "a1b2c3d4", 1)));
        when(notificationPreferenceService.shouldEmailShareNotify(7L)).thenReturn(false);

        adminService.updateShareStatus(5L, -2);

        verify(emailService, never()).sendHtml(anyString(), anyString(), anyString(), anyString());
        verify(emailService, never()).send(anyString(), anyString(), anyString());
    }

    /** IronWall v1.47.10: 开关开启时，分享封禁仍按原样发信。 */
    @Test
    void updateShareStatus_shouldSendShareMailWhenPreferenceOn() {
        when(shareRepository.findById(5L)).thenReturn(Optional.of(share(5L, 7L, "a1b2c3d4", 1)));
        when(notificationPreferenceService.shouldEmailShareNotify(7L)).thenReturn(true);
        when(userRepository.findById(7L)).thenReturn(Optional.of(user(7L, "alice", "alice@example.com")));

        adminService.updateShareStatus(5L, -2);

        verify(emailService).sendHtml(eq("alice@example.com"), anyString(), anyString(), anyString());
    }

    /** IronWall v1.47.10: 关闭“邮箱通知”总开关后，账号封禁不再发信。 */
    @Test
    void updateUserStatus_shouldSkipBanMailWhenEmailNotifyOff() {
        User target = user(7L, "alice", "alice@example.com");
        target.setRole("user");
        target.setUserStatus("active");
        when(userRepository.findById(7L)).thenReturn(Optional.of(target));
        when(notificationPreferenceService.emailNotifyEnabled(7L)).thenReturn(false);

        UpdateUserRequest request = new UpdateUserRequest();
        request.setUserStatus("banned");
        adminService.updateUser(7L, request);

        verify(emailService, never()).sendHtml(anyString(), anyString(), anyString(), anyString());
        verify(emailService, never()).send(anyString(), anyString(), anyString());
    }

    private Share share(Long id, Long userId, String code, int status) {
        Share s = new Share();
        s.setId(id);
        s.setUserId(userId);
        s.setShareCode(code);
        s.setStatus(status);
        return s;
    }

    private User user(Long id, String username, String email) {
        User u = new User();
        u.setId(id);
        u.setUsername(username);
        u.setEmail(email);
        return u;
    }
}
