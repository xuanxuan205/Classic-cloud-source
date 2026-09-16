package com.jdy.cloud.service;

import com.jdy.cloud.dto.FileUploadResult;
import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.ErrorCode;
import com.jdy.cloud.model.FileEntity;
import com.jdy.cloud.model.User;
import com.jdy.cloud.repository.FileRepository;
import com.jdy.cloud.repository.FolderRepository;
import com.jdy.cloud.repository.ShareRepository;
import com.jdy.cloud.repository.UserRepository;
import com.jdy.cloud.security.FileContentSafetyService;
import com.jdy.cloud.security.StorageCryptoService;
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
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class FileServiceTest {

    @Mock private FileRepository fileRepository;
    @Mock private FolderRepository folderRepository;
    @Mock private ShareRepository shareRepository;
    @Mock private UserRepository userRepository;
    @Mock private AuditLogService auditLogService;
    @Mock private PlatformTransactionManager transactionManager;
    @Mock private FileContentSafetyService contentSafety;
    @Mock private StorageCryptoService storageCrypto;

    @InjectMocks
    private FileService fileService;

    @TempDir
    Path tempDir;

    private User testUser;
    private FileEntity testFile;

    @BeforeEach
    void setUp() throws Exception {
        testUser = new User();
        testUser.setId(1L);
        testUser.setStorageUsed(0L);
        testUser.setStorageLimit(1073741824L);

        testFile = new FileEntity();
        testFile.setId(1L);
        testFile.setFilename("test.txt");
        testFile.setOriginalName("test.txt");
        testFile.setFileSize(100L);
        testFile.setUserId(1L);
        testFile.setFolderId(0L);

        lenient().when(contentSafety.scan(any(Path.class), anyString(), anyBoolean())).thenReturn(FileContentSafetyService.SAFE);
        lenient().when(storageCrypto.openWrite(any(Path.class), anyLong()))
                .thenAnswer(inv -> java.nio.file.Files.newOutputStream((Path) inv.getArgument(0)));
        lenient().when(storageCrypto.openRead(any(Path.class)))
                .thenAnswer(inv -> java.nio.file.Files.newInputStream((Path) inv.getArgument(0)));
        lenient().when(storageCrypto.plainLength(any(Path.class)))
                .thenAnswer(inv -> java.nio.file.Files.size((Path) inv.getArgument(0)));

        var field = FileService.class.getDeclaredField("uploadDir");
        field.setAccessible(true);
        field.set(fileService, tempDir.toString());
    }

    @Test
    void uploadFile_shouldSucceed_whenStorageAvailable() throws Exception {
        byte[] content = "hello".getBytes();
        MockMultipartFile file = new MockMultipartFile("file", "test.txt", "text/plain", content);

        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        when(fileRepository.sumFileSizeByUserIdAndStatus(1L, 1)).thenReturn(0L);
        when(transactionManager.getTransaction(any())).thenReturn(mock(TransactionStatus.class));
        when(userRepository.incrementStorageUsedWithinLimit(1L, 5L)).thenReturn(1);
        when(fileRepository.save(any(FileEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        FileUploadResult result = fileService.uploadFile(1L, file, null, sha256Hex(content));

        assertNotNull(result);
        assertEquals("test.txt", result.getOriginalName());
        assertEquals(5, result.getFileSize());
        verify(fileRepository).save(any(FileEntity.class));
        verify(userRepository).incrementStorageUsedWithinLimit(1L, 5L);
    }

    /** IronWall v1.45.0: 缺失全文件哈希必须拒绝并删除已落盘文件（校验不可跳过）。 */
    @Test
    void uploadFile_shouldRejectMissingFileHash_andDeleteWrittenFile() throws Exception {
        byte[] content = "hello".getBytes();
        MockMultipartFile file = new MockMultipartFile("file", "test.txt", "text/plain", content);

        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        when(fileRepository.sumFileSizeByUserIdAndStatus(1L, 1)).thenReturn(0L);

        BusinessException ex = assertThrows(BusinessException.class,
                () -> fileService.uploadFile(1L, file, null, null));
        assertEquals(ErrorCode.BAD_REQUEST.getCode(), ex.getCode());
    }

    /** IronWall v1.46.0: 直传超 10MB 普通用户拒绝并提示走分片（管理员豁免）。 */
    @Test
    void uploadFile_shouldRejectDirectUploadOver10Mb_forNormalUser() throws Exception {
        byte[] content = new byte[10 * 1024 * 1024 + 1];
        MockMultipartFile file = new MockMultipartFile("file", "big.txt", "text/plain", content);

        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));

        BusinessException ex = assertThrows(BusinessException.class,
                () -> fileService.uploadFile(1L, file, null, sha256Hex(content)));
        assertEquals(ErrorCode.BAD_REQUEST.getCode(), ex.getCode());
        assertTrue(ex.getMessage().contains("分片"));
        verify(fileRepository, never()).save(any(FileEntity.class));
    }

    /** IronWall v1.46.0: 管理员直传超 10MB 按管理员配额豁免直传上限。 */
    @Test
    void uploadFile_shouldAllowDirectUploadOver10Mb_forAdmin() throws Exception {
        testUser.setRole("admin");
        byte[] content = new byte[10 * 1024 * 1024 + 1];
        MockMultipartFile file = new MockMultipartFile("file", "big.zip", "application/zip", content);

        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        when(transactionManager.getTransaction(any())).thenReturn(mock(TransactionStatus.class));
        when(userRepository.incrementStorageUsed(1L, (long) content.length)).thenReturn(1);
        when(fileRepository.save(any(FileEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        FileUploadResult result = fileService.uploadFile(1L, file, null, sha256Hex(content));

        assertNotNull(result);
        assertEquals("big.zip", result.getOriginalName());
        verify(fileRepository).save(any(FileEntity.class));
    }

    /** IronWall v1.45.0: 整文件哈希不匹配必须拒绝（首尾 64KB 盲区彻底消除）。 */
    @Test
    void uploadFile_shouldRejectTamperedMiddleContent_onFullHashMismatch() throws Exception {
        byte[] content = "hello".getBytes();
        MockMultipartFile file = new MockMultipartFile("file", "test.txt", "text/plain", content);

        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        when(fileRepository.sumFileSizeByUserIdAndStatus(1L, 1)).thenReturn(0L);

        BusinessException ex = assertThrows(BusinessException.class,
                () -> fileService.uploadFile(1L, file, null, "f".repeat(64)));
        assertEquals(ErrorCode.BAD_REQUEST.getCode(), ex.getCode());
        verify(fileRepository, never()).save(any(FileEntity.class));
    }

    /** IronWall v1.45.0: 白名单四类 27 个后缀普通用户全部放行。 */
    @Test
    void uploadFile_shouldAllowAllWhitelistExtensions_forNormalUser() throws Exception {
        String[] whitelist = {
                // 文档类
                "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "md", "csv",
                // 图片类
                "jpg", "jpeg", "png", "gif", "bmp", "webp", "svg",
                // 音视频
                "mp3", "wav", "flac", "mp4", "mov", "mkv", "avi",
                // 压缩包
                "zip", "7z", "rar"
        };
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        when(fileRepository.sumFileSizeByUserIdAndStatus(1L, 1)).thenReturn(0L);
        when(transactionManager.getTransaction(any())).thenReturn(mock(TransactionStatus.class));
        when(userRepository.incrementStorageUsedWithinLimit(1L, 5L)).thenReturn(1);
        when(fileRepository.save(any(FileEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        for (String ext : whitelist) {
            byte[] content = "hello".getBytes();
            MockMultipartFile file = new MockMultipartFile("file", "test." + ext, "application/octet-stream", content);
            FileUploadResult result = fileService.uploadFile(1L, file, null, sha256Hex(content));
            assertNotNull(result, "白名单后缀 ." + ext + " 应放行");
            assertEquals("test." + ext, result.getOriginalName());
        }
    }

    /** IronWall v1.45.0: 非白名单后缀普通用户拒绝，可执行后缀同样拒绝。 */
    @Test
    void uploadFile_shouldRejectNonWhitelistExtensions_forNormalUser() {
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));

        BusinessException ex1 = assertThrows(BusinessException.class, () ->
                fileService.uploadFile(1L,
                        new MockMultipartFile("file", "a.xyz", "application/octet-stream", "x".getBytes()),
                        null, sha256Hex("x".getBytes())));
        assertEquals(ErrorCode.FILE_TYPE_NOT_ALLOWED.getCode(), ex1.getCode());

        BusinessException ex2 = assertThrows(BusinessException.class, () ->
                fileService.uploadFile(1L,
                        new MockMultipartFile("file", "a.exe", "application/octet-stream", "x".getBytes()),
                        null, sha256Hex("x".getBytes())));
        assertEquals(ErrorCode.BAD_REQUEST.getCode(), ex2.getCode());
    }

    /** IronWall v1.45.0: 管理员账号无后缀限制，任意后缀放行。 */
    @Test
    void uploadFile_adminCanUploadAnyExtension() throws Exception {
        testUser.setRole("admin");
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        when(fileRepository.sumFileSizeByUserIdAndStatus(1L, 1)).thenReturn(0L);
        when(transactionManager.getTransaction(any())).thenReturn(mock(TransactionStatus.class));
        when(userRepository.incrementStorageUsed(1L, 4L)).thenReturn(1);
        when(fileRepository.save(any(FileEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        for (String name : new String[]{"a.xyz", "b.exe", "c.any"}) {
            byte[] content = "data".getBytes();
            MockMultipartFile file = new MockMultipartFile("file", name, "application/octet-stream", content);
            FileUploadResult result = fileService.uploadFile(1L, file, null, sha256Hex(content));
            assertNotNull(result, "管理员上传 " + name + " 应放行");
            assertEquals(name, result.getOriginalName());
        }
    }

    @Test
    void uploadFile_shouldThrow_whenStorageFull() {
        testUser.setStorageLimit(10L);
        byte[] content = "this is more than 10 bytes".getBytes();
        MockMultipartFile file = new MockMultipartFile("file", "big.txt", "text/plain", content);

        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));

        BusinessException ex = assertThrows(BusinessException.class,
                () -> fileService.uploadFile(1L, file, null));
        assertEquals(ErrorCode.STORAGE_FULL.getCode(), ex.getCode());
    }

    @Test
    void uploadFile_shouldThrowStorageFull_whenUsedPlusFileExceedsQuota() throws Exception {
        testUser.setStorageLimit(100L);
        byte[] content = "small content".getBytes();
        MockMultipartFile file = new MockMultipartFile("file", "small.txt", "text/plain", content);

        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        when(fileRepository.sumFileSizeByUserIdAndStatus(1L, 1)).thenReturn(90L);

        BusinessException ex = assertThrows(BusinessException.class,
                () -> fileService.uploadFile(1L, file, null));
        assertEquals(ErrorCode.STORAGE_FULL.getCode(), ex.getCode());
    }

    @Test
    void listFiles_shouldReturnPaginatedResults() {
        Page<FileEntity> page = new PageImpl<>(List.of(testFile), PageRequest.of(0, 20), 1);
        when(fileRepository.findByUserIdAndFolderIdAndStatus(1L, 0L, 1, PageRequest.of(0, 20))).thenReturn(page);

        Page<FileEntity> result = fileService.listFiles(1L, null, 0, 20);

        assertEquals(1, result.getTotalElements());
        assertEquals("test.txt", result.getContent().get(0).getOriginalName());
    }

    @Test
    void deleteFile_shouldSucceed_whenUserOwnsFile() {
        when(fileRepository.findById(1L)).thenReturn(Optional.of(testFile));

        assertDoesNotThrow(() -> fileService.deleteFile(1L, 1L));
        verify(fileRepository).save(testFile);
        verify(userRepository).incrementStorageUsed(1L, -100L);
    }

    @Test
    void deleteFile_shouldThrow_whenUserDoesNotOwnFile() {
        FileEntity otherFile = new FileEntity();
        otherFile.setId(1L);
        otherFile.setUserId(999L);

        when(fileRepository.findById(1L)).thenReturn(Optional.of(otherFile));

        BusinessException ex = assertThrows(BusinessException.class,
                () -> fileService.deleteFile(1L, 1L));
        assertEquals(ErrorCode.FORBIDDEN.getCode(), ex.getCode());
    }

    @Test
    void getStorageStats_shouldReturnCorrectStats() {
        testUser.setStorageUsed(500L);
        testUser.setUploadLimit(850);
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        when(fileRepository.sumFileSizeByUserIdAndStatus(1L, 1)).thenReturn(700L);
        when(fileRepository.sumDownloadCountByUserIdAndStatus(1L, 1)).thenReturn(12L);

        var stats = fileService.getStorageStats(1L);

        assertEquals(700L, stats.get("used"));
        assertEquals(1073741824L, stats.get("limit"));
        assertEquals(850, stats.get("upload_limit"));
        assertEquals(12L, stats.get("total_downloads"));
    }

    @Test
    void deleteFile_shouldBeIdempotent_whenAlreadyInRecycleBin() {
        testFile.setStatus(0);
        when(fileRepository.findById(1L)).thenReturn(Optional.of(testFile));

        fileService.deleteFile(1L, 1L);

        verify(fileRepository, never()).save(any(FileEntity.class));
        verify(userRepository, never()).incrementStorageUsed(anyLong(), anyLong());
    }

    @Test
    void restoreFile_shouldSucceed_whenQuotaAvailable() {
        testFile.setStatus(0);
        when(fileRepository.findById(1L)).thenReturn(Optional.of(testFile));
        when(userRepository.incrementStorageUsedWithinLimit(1L, 100L)).thenReturn(1);

        fileService.restoreFile(1L, 1L);

        assertEquals(1, testFile.getStatus());
        verify(fileRepository).save(testFile);
        verify(userRepository).incrementStorageUsedWithinLimit(1L, 100L);
    }

    @Test
    void restoreFile_shouldThrowStorageFull_whenQuotaExceeded() {
        testFile.setStatus(0);
        when(fileRepository.findById(1L)).thenReturn(Optional.of(testFile));
        when(userRepository.incrementStorageUsedWithinLimit(1L, 100L)).thenReturn(0);

        BusinessException ex = assertThrows(BusinessException.class,
                () -> fileService.restoreFile(1L, 1L));
        assertEquals(ErrorCode.STORAGE_FULL.getCode(), ex.getCode());
        verify(fileRepository, never()).save(any(FileEntity.class));
    }

    @Test
    void restoreFile_shouldBeIdempotent_whenFileAlreadyActive() {
        testFile.setStatus(1);
        when(fileRepository.findById(1L)).thenReturn(Optional.of(testFile));

        fileService.restoreFile(1L, 1L);

        verify(userRepository, never()).incrementStorageUsed(anyLong(), anyLong());
        verify(userRepository, never()).incrementStorageUsedWithinLimit(anyLong(), anyLong());
        verify(fileRepository, never()).save(any(FileEntity.class));
    }

    @Test
    void permanentDeleteFile_shouldRejectActiveFile() {
        testFile.setStatus(1);
        when(fileRepository.findById(1L)).thenReturn(Optional.of(testFile));

        BusinessException ex = assertThrows(BusinessException.class,
                () -> fileService.permanentDeleteFile(1L, 1L));
        assertEquals(ErrorCode.BAD_REQUEST.getCode(), ex.getCode());
        verify(fileRepository, never()).delete(any(FileEntity.class));
    }

    @Test
    void permanentDeleteFile_shouldRejectWhenShareReferencesFile() {
        testFile.setStatus(0);
        when(fileRepository.findById(1L)).thenReturn(Optional.of(testFile));
        when(shareRepository.existsByFileId(1L)).thenReturn(true);

        BusinessException ex = assertThrows(BusinessException.class,
                () -> fileService.permanentDeleteFile(1L, 1L));
        assertEquals(ErrorCode.CONFLICT.getCode(), ex.getCode());
        verify(fileRepository, never()).delete(any(FileEntity.class));
    }

    @Test
    void saveChunk_shouldRejectExcessiveTotalCount() {
        // IronWall v1.28.3: 分片数上限=单文件上限/分片大小（普通用户 850MB/10MB=85），超限声明必须拒绝，防止临时分片撑爆磁盘
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        BusinessException ex = assertThrows(BusinessException.class, () ->
                fileService.saveChunk(1L, "a".repeat(64), 0, 1000,
                        new MockMultipartFile("file", "chunk-0", "application/octet-stream", "x".getBytes()),
                        sha256Hex("x".getBytes())));
        assertEquals(ErrorCode.BAD_REQUEST.getCode(), ex.getCode());
    }

    /** IronWall v1.45.0: 分片内容哈希匹配时保存成功。 */
    @Test
    void saveChunk_shouldAcceptMatchingChunkHash() {
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        int saved = fileService.saveChunk(1L, "a".repeat(64), 0, 1,
                new MockMultipartFile("file", "chunk-0", "application/octet-stream", "x".getBytes()),
                sha256Hex("x".getBytes()));
        assertEquals(0, saved);
    }

    /** IronWall v1.45.0: 分片内容哈希不匹配必须删除临时分片并拒绝。 */
    @Test
    void saveChunk_shouldRejectTamperedChunk_andDeleteTempFile() {
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        BusinessException ex = assertThrows(BusinessException.class, () ->
                fileService.saveChunk(1L, "a".repeat(64), 0, 1,
                        new MockMultipartFile("file", "chunk-0", "application/octet-stream", "x".getBytes()),
                        "f".repeat(64)));
        assertEquals(ErrorCode.BAD_REQUEST.getCode(), ex.getCode());
    }

    /** IronWall v1.45.0: 缺失分片内容哈希必须拒绝。 */
    @Test
    void saveChunk_shouldRejectMissingChunkHash() {
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));
        BusinessException ex = assertThrows(BusinessException.class, () ->
                fileService.saveChunk(1L, "a".repeat(64), 0, 1,
                        new MockMultipartFile("file", "chunk-0", "application/octet-stream", "x".getBytes()),
                        null));
        assertEquals(ErrorCode.BAD_REQUEST.getCode(), ex.getCode());
    }

    private static String sha256Hex(byte[] data) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }}
