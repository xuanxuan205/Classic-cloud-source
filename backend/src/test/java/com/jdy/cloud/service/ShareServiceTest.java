package com.jdy.cloud.service;

import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.dto.CreateShareRequest;
import com.jdy.cloud.exception.ErrorCode;
import com.jdy.cloud.model.FileEntity;
import com.jdy.cloud.model.Folder;
import com.jdy.cloud.model.Share;
import com.jdy.cloud.repository.FileRepository;
import com.jdy.cloud.repository.FolderRepository;
import com.jdy.cloud.repository.ShareRepository;
import com.jdy.cloud.repository.UserRepository;
import com.jdy.cloud.security.ShareLinkSigner;
import com.jdy.cloud.security.StorageCryptoService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ShareServiceTest {

    @Mock private ShareRepository shareRepository;
    @Mock private FileRepository fileRepository;
    @Mock private UserRepository userRepository;
    @Mock private FolderRepository folderRepository;
    @Mock private AuditLogService auditLogService;
    @Mock private ShareLinkSigner shareLinkSigner;
    @Mock private StorageCryptoService storageCrypto;

    @InjectMocks
    private ShareService shareService;

    @TempDir
    Path tempDir;

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
        // IronWall v1.46.0: 下载凭证强制校验——默认放行有效 sig，无效用例单独覆盖。
        lenient().when(shareLinkSigner.verify(anyString(), any(), any(), any(), any())).thenReturn(true);
    }

    @Test
    void downloadSharedFile_shouldThrowFolderNotFound_whenFolderIdIsNull() {
        share.setShareType(2);
        share.setFolderId(null);
        share.setFileId(null);

        FileEntity file = new FileEntity();
        file.setId(10L);
        file.setFolderId(5L);
        file.setFilename("x.bin");
        file.setOriginalName("x.txt");

        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));
        when(fileRepository.findById(10L)).thenReturn(Optional.of(file));

        BusinessException ex = assertThrows(BusinessException.class,
                () -> shareService.downloadSharedFile("a1b2c3d4", null, null, 10L, "sig"));
        assertEquals(ErrorCode.FOLDER_NOT_FOUND.getCode(), ex.getCode());
    }

    @Test
    void downloadSharedFile_shouldThrowFileNotFound_whenFilenameIsNull() {
        FileEntity file = new FileEntity();
        file.setId(20L);
        file.setFilename(null);
        file.setOriginalName("x.txt");

        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));
        when(fileRepository.findById(20L)).thenReturn(Optional.of(file));

        BusinessException ex = assertThrows(BusinessException.class,
                () -> shareService.downloadSharedFile("a1b2c3d4", null, null, null, "sig"));
        assertEquals(ErrorCode.FILE_NOT_FOUND.getCode(), ex.getCode());
    }

    @Test
    void downloadSharedFolderAsZip_shouldSkipFilesWithNullNames() throws Exception {
        share.setShareType(2);
        share.setFolderId(7L);
        share.setFileId(null);

        Folder folder = new Folder();
        folder.setId(7L);
        folder.setName("测试目录");

        FileEntity broken = new FileEntity();
        broken.setId(30L);
        broken.setFilename(null);
        broken.setOriginalName(null);

        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));
        when(folderRepository.findById(7L)).thenReturn(Optional.of(folder));
        when(fileRepository.findByFolderIdAndStatus(7L, 1)).thenReturn(List.of(broken));

        when(shareRepository.incrementDownloadCountIfAllowed(1L)).thenReturn(1);

        byte[] zip = shareService.downloadSharedFolderAsZip("a1b2c3d4", null, null, "sig");

        assertNotNull(zip);
        assertTrue(zip.length > 0);
        verify(shareRepository).incrementDownloadCountIfAllowed(1L);
    }

    @Test
    void downloadSharedFile_shouldThrowLimitReached_whenAtomicIncrementReturnsZero() {
        share.setDownloadLimit(1);
        share.setDownloadCount(0);

        FileEntity file = new FileEntity();
        file.setId(20L);
        file.setFilename("x.bin");
        file.setOriginalName("x.txt");

        Share latest = new Share();
        latest.setId(1L);
        latest.setDownloadLimit(1);
        latest.setDownloadCount(1);

        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));
        when(fileRepository.findById(20L)).thenReturn(Optional.of(file));
        when(shareRepository.incrementDownloadCountIfAllowed(1L)).thenReturn(0);
        when(shareRepository.findById(1L)).thenReturn(Optional.of(latest));

        BusinessException ex = assertThrows(BusinessException.class,
                () -> shareService.downloadSharedFile("a1b2c3d4", null, null, null, "sig"));
        assertEquals(ErrorCode.SHARE_LIMIT_REACHED.getCode(), ex.getCode());
    }

    @Test
    void downloadSharedFile_shouldThrowNotFound_whenAtomicFailsAndShareGone() {
        FileEntity file = new FileEntity();
        file.setId(20L);
        file.setFilename("x.bin");
        file.setOriginalName("x.txt");

        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));
        when(fileRepository.findById(20L)).thenReturn(Optional.of(file));
        when(shareRepository.incrementDownloadCountIfAllowed(1L)).thenReturn(0);
        when(shareRepository.findById(1L)).thenReturn(Optional.empty());

        BusinessException ex = assertThrows(BusinessException.class,
                () -> shareService.downloadSharedFile("a1b2c3d4", null, null, null, "sig"));
        assertEquals(ErrorCode.SHARE_NOT_FOUND.getCode(), ex.getCode());
    }

    @Test
    void downloadSharedFile_shouldRejectMissingSig() {
        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));
        doReturn(false).when(shareLinkSigner).verify(anyString(), any(), any(), any(), any());

        BusinessException ex = assertThrows(BusinessException.class,
                () -> shareService.downloadSharedFile("a1b2c3d4", null, null, null, null));
        assertEquals(ErrorCode.SHARE_SIG_INVALID.getCode(), ex.getCode());
        verify(fileRepository, never()).findById(anyLong());
    }

    @Test
    void downloadSharedFile_shouldRejectWrongSig() {
        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));
        doReturn(false).when(shareLinkSigner).verify(anyString(), any(), any(), any(), any());

        BusinessException ex = assertThrows(BusinessException.class,
                () -> shareService.downloadSharedFile("a1b2c3d4", null, null, null, "deadbeef".repeat(5)));
        assertEquals(ErrorCode.SHARE_SIG_INVALID.getCode(), ex.getCode());
        verify(fileRepository, never()).findById(anyLong());
    }

    /** IronWall v1.47.0: 文件被管理员封禁(status=0)后，公开分享不可下载。 */
    @Test
    void downloadSharedFile_shouldReject_whenSharedFileBanned() {
        FileEntity file = new FileEntity();
        file.setId(20L);
        file.setFilename("x.bin");
        file.setOriginalName("x.txt");
        file.setStatus(0);

        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));
        when(fileRepository.findById(20L)).thenReturn(Optional.of(file));

        BusinessException ex = assertThrows(BusinessException.class,
                () -> shareService.downloadSharedFile("a1b2c3d4", null, null, null, "sig"));
        assertEquals(ErrorCode.FILE_NOT_FOUND.getCode(), ex.getCode());
        verify(shareRepository, never()).incrementDownloadCountIfAllowed(anyLong());
    }

    /** IronWall v1.47.0: 文件被永久删除(status=-1)后，公开分享不可下载。 */
    @Test
    void downloadSharedFile_shouldReject_whenSharedFileDeleted() {
        FileEntity file = new FileEntity();
        file.setId(20L);
        file.setFilename("x.bin");
        file.setOriginalName("x.txt");
        file.setStatus(-1);

        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));
        when(fileRepository.findById(20L)).thenReturn(Optional.of(file));

        BusinessException ex = assertThrows(BusinessException.class,
                () -> shareService.downloadSharedFile("a1b2c3d4", null, null, null, "sig"));
        assertEquals(ErrorCode.FILE_NOT_FOUND.getCode(), ex.getCode());
    }

    /** IronWall v1.47.0: 文件解封/还原(status=1)后分享自动恢复可下载。 */
    @Test
    void downloadSharedFile_shouldAllow_whenSharedFileRestored() {
        FileEntity file = new FileEntity();
        file.setId(20L);
        file.setFilename("x.bin");
        file.setOriginalName("x.txt");
        file.setStatus(1);

        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));
        when(fileRepository.findById(20L)).thenReturn(Optional.of(file));
        when(shareRepository.incrementDownloadCountIfAllowed(1L)).thenReturn(1);

        FileEntity result = shareService.downloadSharedFile("a1b2c3d4", null, null, null, "sig");

        assertNotNull(result);
        assertEquals(20L, result.getId());
    }

    /** IronWall v1.47.0: 文件夹分享内单个文件被删后不可下载。 */
    @Test
    void downloadSharedFile_folderShare_shouldRejectDeletedFile() {
        share.setShareType(2);
        share.setFolderId(5L);
        share.setFileId(null);

        FileEntity file = new FileEntity();
        file.setId(10L);
        file.setFolderId(5L);
        file.setFilename("y.bin");
        file.setOriginalName("y.txt");
        file.setStatus(0);

        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));
        when(fileRepository.findById(10L)).thenReturn(Optional.of(file));

        BusinessException ex = assertThrows(BusinessException.class,
                () -> shareService.downloadSharedFile("a1b2c3d4", null, null, 10L, "sig"));
        assertEquals(ErrorCode.FILE_NOT_FOUND.getCode(), ex.getCode());
    }

    /** IronWall v1.47.0: 分享详情页遇文件已删除 → 分享置失效。 */
    @Test
    void getShareInfo_shouldInvalidateShare_whenSharedFileDeleted() {
        FileEntity file = new FileEntity();
        file.setId(20L);
        file.setOriginalName("x.txt");
        file.setFileSize(10L);
        file.setStatus(-1);

        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));
        when(fileRepository.findById(20L)).thenReturn(Optional.of(file));

        BusinessException ex = assertThrows(BusinessException.class,
                () -> shareService.getShareInfo("a1b2c3d4", null, null));
        assertEquals(ErrorCode.SHARE_EXPIRED.getCode(), ex.getCode());
        assertEquals(0, share.getStatus());
        verify(shareRepository).save(share);
    }

    @Test
    void downloadSharedFolderAsZip_shouldRejectMissingSig() {
        share.setShareType(2);
        share.setFolderId(7L);
        share.setFileId(null);
        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));
        doReturn(false).when(shareLinkSigner).verify(anyString(), any(), any(), any(), any());

        BusinessException ex = assertThrows(BusinessException.class,
                () -> shareService.downloadSharedFolderAsZip("a1b2c3d4", null, null, null));
        assertEquals(ErrorCode.SHARE_SIG_INVALID.getCode(), ex.getCode());
    }

    @Test
    void getShareInfo_shouldNormalizeShareCodeToLowercase() {
        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));
        FileEntity normFile = new FileEntity();
        normFile.setId(20L);
        normFile.setOriginalName("x.txt");
        normFile.setFileSize(10L);
        when(fileRepository.findById(20L)).thenReturn(Optional.of(normFile));
        when(userRepository.findById(1L)).thenReturn(Optional.of(new com.jdy.cloud.model.User()));

        Map<String, Object> info = shareService.getShareInfo("a1b2c3d4", null, null);

        assertNotNull(info);
        assertEquals("a1b2c3d4", info.get("share_code"));
        verify(shareRepository).findByShareCode("a1b2c3d4");
    }

    @Test
    void createShare_shouldRejectPasswordLongerThan10() {
        FileEntity file = new FileEntity();
        file.setId(20L);
        file.setUserId(1L);
        file.setOriginalName("a.txt");
        when(fileRepository.findById(20L)).thenReturn(Optional.of(file));

        CreateShareRequest request = new CreateShareRequest();
        request.setFileId(20L);
        request.setPassword("12345678901");

        BusinessException ex = assertThrows(BusinessException.class,
                () -> shareService.createShare(1L, request));
        assertEquals(ErrorCode.BAD_REQUEST.getCode(), ex.getCode());
        verify(shareRepository, never()).save(any(Share.class));
    }

    @Test
    void createShare_shouldRejectPasswordShorterThan4() {
        FileEntity file = new FileEntity();
        file.setId(20L);
        file.setUserId(1L);
        file.setOriginalName("a.txt");
        when(fileRepository.findById(20L)).thenReturn(Optional.of(file));

        CreateShareRequest request = new CreateShareRequest();
        request.setFileId(20L);
        request.setPassword("123");

        BusinessException ex = assertThrows(BusinessException.class,
                () -> shareService.createShare(1L, request));
        assertEquals(ErrorCode.BAD_REQUEST.getCode(), ex.getCode());
        verify(shareRepository, never()).save(any(Share.class));
    }

    @Test
    void createShare_shouldAcceptPasswordOf10Chars() {
        FileEntity file = new FileEntity();
        file.setId(20L);
        file.setUserId(1L);
        file.setOriginalName("a.txt");
        when(fileRepository.findById(20L)).thenReturn(Optional.of(file));
        when(shareRepository.save(any(Share.class))).thenAnswer(inv -> inv.getArgument(0));

        CreateShareRequest request = new CreateShareRequest();
        request.setFileId(20L);
        request.setPassword("1234567890");

        Share saved = shareService.createShare(1L, request);

        assertNotNull(saved);
        // IronWall v1.28.9: 密码只存加盐哈希，不再保存明文
        assertEquals(PasswordGuardService.hashSharePassword(saved.getShareCode(), "1234567890"), saved.getPassword());
        assertFalse(saved.getPassword().contains("1234567890"));
        verify(shareRepository).save(any(Share.class));
    }

    /** IronWall v1.47.4: 单文件分享下载必须同步计入文件下载次数（管理端文件/下载统计数据源）。 */
    @Test
    void downloadSharedFile_shouldAlsoIncrementFileDownloadCount() {
        FileEntity file = new FileEntity();
        file.setId(20L);
        file.setFilename("x.bin");
        file.setOriginalName("x.txt");
        file.setStatus(1);

        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));
        when(fileRepository.findById(20L)).thenReturn(Optional.of(file));
        when(shareRepository.incrementDownloadCountIfAllowed(1L)).thenReturn(1);

        FileEntity result = shareService.downloadSharedFile("a1b2c3d4", null, null, null, "sig");

        assertNotNull(result);
        verify(fileRepository).incrementDownloadCount(20L);
    }

    /** IronWall v1.47.4: 文件夹分享内单文件下载同样计入该文件下载次数。 */
    @Test
    void downloadSharedFile_folderShare_shouldAlsoIncrementFileDownloadCount() {
        share.setShareType(2);
        share.setFolderId(5L);
        share.setFileId(null);

        FileEntity file = new FileEntity();
        file.setId(10L);
        file.setFolderId(5L);
        file.setFilename("y.bin");
        file.setOriginalName("y.txt");
        file.setStatus(1);

        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));
        when(fileRepository.findById(10L)).thenReturn(Optional.of(file));
        when(shareRepository.incrementDownloadCountIfAllowed(1L)).thenReturn(1);

        FileEntity result = shareService.downloadSharedFile("a1b2c3d4", null, null, 10L, "sig");

        assertNotNull(result);
        verify(fileRepository).incrementDownloadCount(10L);
    }

    /** IronWall v1.47.4: 文件夹打包下载对每个成功写入的文件计入下载次数。 */
    @Test
    void downloadSharedFolderAsZip_shouldIncrementFileDownloadCountForIncludedFiles() throws Exception {
        var field = ShareService.class.getDeclaredField("uploadDir");
        field.setAccessible(true);
        field.set(shareService, tempDir.toString());

        share.setShareType(2);
        share.setFolderId(7L);
        share.setFileId(null);

        Folder folder = new Folder();
        folder.setId(7L);
        folder.setName("测试目录");

        Files.write(tempDir.resolve("z.bin"), new byte[]{9, 8, 7});
        FileEntity included = new FileEntity();
        included.setId(30L);
        included.setFilename("z.bin");
        included.setOriginalName("z.txt");
        included.setStatus(1);

        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));
        when(folderRepository.findById(7L)).thenReturn(Optional.of(folder));
        when(fileRepository.findByFolderIdAndStatus(7L, 1)).thenReturn(List.of(included));
        when(shareRepository.incrementDownloadCountIfAllowed(1L)).thenReturn(1);
        when(storageCrypto.openRead(any(Path.class)))
                .thenAnswer(inv -> Files.newInputStream((Path) inv.getArgument(0)));

        byte[] zip = shareService.downloadSharedFolderAsZip("a1b2c3d4", null, null, "sig");

        assertNotNull(zip);
        assertTrue(zip.length > 0);
        verify(fileRepository).incrementDownloadCount(30L);
    }

    /** IronWall v1.47.9: 嵌套子文件夹内的文件必须进入打包（修复）。 */
    @Test
    void downloadSharedFolderAsZip_shouldIncludeNestedFolderFiles() throws Exception {
        var field = ShareService.class.getDeclaredField("uploadDir");
        field.setAccessible(true);
        field.set(shareService, tempDir.toString());

        share.setShareType(2);
        share.setFolderId(7L);
        share.setFileId(null);

        Folder root = new Folder();
        root.setId(7L);
        root.setName("根目录");
        Folder child = new Folder();
        child.setId(8L);
        child.setName("子目录");

        Files.write(tempDir.resolve("root.bin"), new byte[]{1});
        Files.write(tempDir.resolve("child.bin"), new byte[]{2});

        FileEntity rootFile = new FileEntity();
        rootFile.setId(30L);
        rootFile.setFilename("root.bin");
        rootFile.setOriginalName("root.txt");
        FileEntity childFile = new FileEntity();
        childFile.setId(31L);
        childFile.setFilename("child.bin");
        childFile.setOriginalName("child.txt");

        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));
        when(folderRepository.findById(7L)).thenReturn(Optional.of(root));
        when(fileRepository.findByFolderIdAndStatus(7L, 1)).thenReturn(List.of(rootFile));
        when(folderRepository.findByParentIdAndStatus(7L, 1)).thenReturn(List.of(child));
        when(fileRepository.findByFolderIdAndStatus(8L, 1)).thenReturn(List.of(childFile));
        when(shareRepository.incrementDownloadCountIfAllowed(1L)).thenReturn(1);
        when(storageCrypto.openRead(any(Path.class)))
                .thenAnswer(inv -> Files.newInputStream((Path) inv.getArgument(0)));

        byte[] zipBytes = shareService.downloadSharedFolderAsZip("a1b2c3d4", null, null, "sig");

        java.util.Set<String> names = new java.util.HashSet<>();
        try (java.util.zip.ZipInputStream zin = new java.util.zip.ZipInputStream(
                new java.io.ByteArrayInputStream(zipBytes))) {
            java.util.zip.ZipEntry entry;
            while ((entry = zin.getNextEntry()) != null) {
                names.add(entry.getName());
            }
        }
        assertTrue(names.contains("root.txt"), "根目录文件应打包");
        assertTrue(names.contains("子目录/child.txt"), "嵌套子目录文件应打包");
    }

    /** IronWall v1.47.9: 超条目上限必须拒绝打包（防压缩炸弹）。 */
    @Test
    void downloadSharedFolderAsZip_shouldRejectWhenTooManyEntries() throws Exception {
        var maxField = ShareService.class.getDeclaredField("shareZipMaxEntries");
        maxField.setAccessible(true);
        maxField.set(shareService, 1);

        share.setShareType(2);
        share.setFolderId(7L);
        share.setFileId(null);

        Folder root = new Folder();
        root.setId(7L);
        root.setName("根目录");

        FileEntity f1 = new FileEntity();
        f1.setId(30L);
        f1.setFilename("a.bin");
        f1.setOriginalName("a.txt");
        FileEntity f2 = new FileEntity();
        f2.setId(31L);
        f2.setFilename("b.bin");
        f2.setOriginalName("b.txt");

        when(shareRepository.findByShareCode("a1b2c3d4")).thenReturn(Optional.of(share));
        when(folderRepository.findById(7L)).thenReturn(Optional.of(root));
        when(fileRepository.findByFolderIdAndStatus(7L, 1)).thenReturn(List.of(f1, f2));
        when(shareRepository.incrementDownloadCountIfAllowed(1L)).thenReturn(1);

        BusinessException ex = assertThrows(BusinessException.class,
                () -> shareService.downloadSharedFolderAsZip("a1b2c3d4", null, null, "sig"));
        assertEquals(ErrorCode.BAD_REQUEST.getCode(), ex.getCode());
    }
}
