package com.jdy.cloud.service;

import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.ErrorCode;
import com.jdy.cloud.model.FileEntity;
import com.jdy.cloud.model.Share;
import com.jdy.cloud.repository.FileRepository;
import com.jdy.cloud.repository.FolderRepository;
import com.jdy.cloud.repository.ShareRepository;
import com.jdy.cloud.repository.UserRepository;
import com.jdy.cloud.security.ShareLinkSigner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * IronWall v1.38.0: 分享下载审计路径契约测试。
 * 过期分享回写状态并给出专属错误码；封禁分享专属提示；正常下载审计落库。
 */
@ExtendWith(MockitoExtension.class)
class ShareExpiryAuditTest {

    @Mock private ShareRepository shareRepository;
    @Mock private FileRepository fileRepository;
    @Mock private UserRepository userRepository;
    @Mock private FolderRepository folderRepository;
    @Mock private AuditLogService auditLogService;
    @Mock private ShareLinkSigner shareLinkSigner;

    @InjectMocks
    private ShareService shareService;

    private Share share;

    @BeforeEach
    void setUp() {
        share = new Share();
        share.setId(1L);
        share.setShareCode("a1b2c3d4");
        share.setShareType(1);
        share.setFileId(20L);
        share.setStatus(1);
        share.setDownloadLimit(-1);
        share.setDownloadCount(0);
        share.setUserId(1L);
        // IronWall v1.46.0: 下载凭证强制校验——本类聚焦过期/封禁/审计契约，默认放行有效 sig。
        lenient().when(shareLinkSigner.verify(anyString(), any(), any(), any(), any())).thenReturn(true);
    }

    @Test
    void expiredShare_shouldRewriteStatusAndThrowDedicatedCode() {
        share.setExpireTime(LocalDateTime.now().minusMinutes(1));
        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));

        BusinessException ex = assertThrows(BusinessException.class,
                () -> shareService.downloadSharedFile("a1b2c3d4", null, null, null, "sig"));
        assertEquals(ErrorCode.SHARE_EXPIRED.getCode(), ex.getCode());
        assertEquals(0, share.getStatus(), "expired share must be marked invalid and persisted");
        verify(shareRepository).save(share);
        verify(fileRepository, never()).findById(anyLong());
    }

    @Test
    void bannedShare_shouldThrowDedicatedCode() {
        share.setStatus(-2);
        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));

        BusinessException ex = assertThrows(BusinessException.class,
                () -> shareService.downloadSharedFile("a1b2c3d4", null, null, null, "sig"));
        assertEquals(ErrorCode.SHARE_BANNED.getCode(), ex.getCode());
        verify(shareRepository, never()).save(any());
    }

    @Test
    void normalDownload_shouldReturnFileAndAudit() {
        FileEntity file = new FileEntity();
        file.setId(20L);
        file.setFilename("stored-name.bin");
        file.setOriginalName("report.pdf");
        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));
        when(fileRepository.findById(20L)).thenReturn(Optional.of(file));
        when(shareRepository.incrementDownloadCountIfAllowed(1L)).thenReturn(1);

        FileEntity result = shareService.downloadSharedFile("a1b2c3d4", null, null, null, "sig");

        assertSame(file, result);
        // IronWall v1.47.11: 访客下载必须记为 share_download，不得再记成分享者本人的 download
        verify(auditLogService).logShareDownload(1L, "a1b2c3d4", "report.pdf");
        verify(auditLogService, never()).logDownload(anyLong(), anyString(), anyString());
    }

    @Test
    void expiredFolderZip_shouldThrowDedicatedCode() {
        share.setShareType(2);
        share.setFolderId(5L);
        share.setExpireTime(LocalDateTime.now().minusSeconds(1));
        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));

        BusinessException ex = assertThrows(BusinessException.class,
                () -> shareService.downloadSharedFolderAsZip("a1b2c3d4", null, null, "sig"));
        assertEquals(ErrorCode.SHARE_EXPIRED.getCode(), ex.getCode());
        assertEquals(0, share.getStatus());
        verify(shareRepository).save(share);
    }
}
