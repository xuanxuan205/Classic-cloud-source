package com.jdy.cloud.controller;

import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.ErrorCode;
import com.jdy.cloud.model.FileEntity;
import com.jdy.cloud.repository.FileRepository;
import com.jdy.cloud.repository.FolderRepository;
import com.jdy.cloud.repository.ShareRepository;
import com.jdy.cloud.security.SharePasswordLimiter;
import com.jdy.cloud.security.UserPrincipal;
import com.jdy.cloud.security.ShareLookupLimiter;
import com.jdy.cloud.security.ShareDownloadLimiter;
import com.jdy.cloud.security.ShareLinkSigner;
import com.jdy.cloud.security.StorageCryptoService;
import com.jdy.cloud.service.PasswordGuardService;
import com.jdy.cloud.service.ShareService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.io.FileSystemResource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * IronWall v1.6 / v1.7 、: 分享下载控制器链路测试。
 */
@ExtendWith(MockitoExtension.class)
class ShareControllerTest {

    @Mock private ShareService shareService;
    @Mock private ShareRepository shareRepository;
    @Mock private FileRepository fileRepository;
    @Mock private FolderRepository folderRepository;
    @Mock private PasswordGuardService passwordGuardService;
    @Mock private SharePasswordLimiter sharePasswordLimiter;
    @Mock private ShareLookupLimiter shareLookupLimiter;
    @Mock private ShareDownloadLimiter shareDownloadLimiter;
    @Mock private ShareLinkSigner shareLinkSigner;
    @Mock private StorageCryptoService storageCrypto;

    private ShareController controller;
    private Path tempDir;

    @BeforeEach
    void setUp() throws Exception {
        controller = new ShareController(shareService, shareRepository, fileRepository,
                folderRepository, passwordGuardService, sharePasswordLimiter, shareLookupLimiter,
                shareDownloadLimiter, shareLinkSigner, storageCrypto);
        tempDir = Files.createTempDirectory("share-test-");
        ReflectionTestUtils.setField(controller, "uploadDir", tempDir.toString());
    }

    // IronWall v1.25.0: 分享列表分页兼容 1-based 页码（page=1 即第一页）
    @Test
    void list_shouldTreatPageOneAsFirstPage() {
        UserPrincipal principal = new UserPrincipal(7L, "tester", "USER");
        Page<com.jdy.cloud.model.Share> emptyPage = new PageImpl<>(java.util.List.of(), PageRequest.of(0, 20), 0);
        when(shareService.listShares(7L, 0, 20)).thenReturn(emptyPage);

        var response = controller.list(principal, 1, 20);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        verify(shareService).listShares(7L, 0, 20);
    }

    @Test
    void download_shouldReturn200_whenFileExistsOnDisk() throws Exception {
        Path file = tempDir.resolve("abc123.bin");
        Files.write(file, "hello".getBytes(StandardCharsets.UTF_8));

        FileEntity entity = new FileEntity();
        entity.setId(69L);
        entity.setFilename("abc123.bin");
        entity.setOriginalName("测试文件.bin");

        when(shareService.downloadSharedFile("7199784e", null, null, null, null)).thenReturn(entity);
        when(storageCrypto.resourceOf(any(Path.class)))
                .thenAnswer(inv -> new FileSystemResource((Path) inv.getArgument(0)));

        ResponseEntity<?> resp = controller.download("7199784e", null, null, null, null, new MockHttpServletRequest());

        assertEquals(HttpStatus.OK, resp.getStatusCode());
        assertInstanceOf(FileSystemResource.class, resp.getBody());
        assertTrue(resp.getHeaders().getFirst("Content-Disposition").contains("attachment"));
        verify(sharePasswordLimiter).clear(eq("7199784e"), anyString());
        verify(shareDownloadLimiter).checkAllowed(eq("7199784e"), anyString(), anyBoolean(), any());
    }

    @Test
    void download_shouldEnforceShareDownloadLimiter() {
        doThrow(new BusinessException(ErrorCode.TOO_MANY_REQUESTS))
                .when(shareDownloadLimiter).checkAllowed(eq("flood"), anyString(), anyBoolean(), any());

        BusinessException ex = assertThrows(BusinessException.class,
                () -> controller.download("flood", null, null, null, null, new MockHttpServletRequest()));

        assertEquals(ErrorCode.TOO_MANY_REQUESTS.getCode(), ex.getCode());
        verify(shareService, never()).downloadSharedFile(anyString(), any(), any(), any(), any());
    }

    @Test
    void download_shouldReturn404_whenFileMissingOnDisk() throws Exception {
        FileEntity entity = new FileEntity();
        entity.setId(69L);
        entity.setFilename("missing.bin");
        entity.setOriginalName("missing.bin");

        when(shareService.downloadSharedFile("7199784e", null, null, null, null)).thenReturn(entity);

        ResponseEntity<?> resp = controller.download("7199784e", null, null, null, null, new MockHttpServletRequest());

        assertEquals(HttpStatus.NOT_FOUND, resp.getStatusCode());
    }

    @Test
    void download_shouldRethrowBusinessException() {
        when(shareService.downloadSharedFile("badcode", null, null, null, null))
                .thenThrow(new BusinessException(ErrorCode.SHARE_EXPIRED));

        assertThrows(BusinessException.class,
                () -> controller.download("badcode", null, null, null, null, new MockHttpServletRequest()));
    }

    @Test
    void download_shouldRecordFailure_whenPasswordWrong() {
        when(shareService.downloadSharedFile("pcode", "bad", "tok", null, null))
                .thenThrow(new BusinessException(ErrorCode.SHARE_WRONG_PASSWORD));

        assertThrows(BusinessException.class,
                () -> controller.download("pcode", "bad", "tok", null, null, new MockHttpServletRequest()));
        verify(sharePasswordLimiter).recordFailure(eq("pcode"), anyString());
    }

    // IronWall v1.47.0: 分享详情页错误密码同样记失败次数，且错误码原样抛出
    @Test
    void getShareInfo_shouldRecordFailure_whenPasswordWrong() {
        when(shareService.getShareInfo("pcode", "bad", "tok"))
                .thenThrow(new BusinessException(ErrorCode.SHARE_WRONG_PASSWORD));

        BusinessException ex = assertThrows(BusinessException.class,
                () -> controller.getShareInfo("pcode", "bad", "tok", new MockHttpServletRequest()));

        assertEquals(ErrorCode.SHARE_WRONG_PASSWORD.getCode(), ex.getCode());
        verify(sharePasswordLimiter).recordFailure(eq("pcode"), anyString());
    }

    @Test
    void download_shouldReturn500Json_whenUnexpectedError() {
        when(shareService.downloadSharedFile("boom", null, null, null, null))
                .thenThrow(new RuntimeException("db down"));

        ResponseEntity<?> resp = controller.download("boom", null, null, null, null, new MockHttpServletRequest());

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, resp.getStatusCode());
        assertNotNull(resp.getBody());
    }

    @Test
    void downloadNoCode_shouldReturn404() {
        assertEquals(HttpStatus.NOT_FOUND, controller.downloadNoCode().getStatusCode());
        assertEquals(HttpStatus.NOT_FOUND, controller.downloadZipNoCode().getStatusCode());
        assertEquals(HttpStatus.NOT_FOUND, controller.shareRoot().getStatusCode());
    }

    @Test
    void list_shouldRejectAnonymousWith401() {
        BusinessException ex = assertThrows(BusinessException.class,
                () -> controller.list(null, 0, 20));
        assertEquals(ErrorCode.UNAUTHORIZED.getCode(), ex.getCode());
    }
}
