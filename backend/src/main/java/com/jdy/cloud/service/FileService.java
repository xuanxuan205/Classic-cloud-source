package com.jdy.cloud.service;

import com.jdy.cloud.dto.FileUploadResult;
import com.jdy.cloud.util.SecurityUtils;
import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.ErrorCode;
import com.jdy.cloud.model.FileEntity;
import com.jdy.cloud.model.Folder;
import com.jdy.cloud.model.User;
import com.jdy.cloud.repository.AuditLogRepository;
import com.jdy.cloud.repository.FileRepository;
import com.jdy.cloud.repository.FolderRepository;
import com.jdy.cloud.repository.ShareRepository;
import com.jdy.cloud.security.FileContentSafetyService;
import com.jdy.cloud.security.UploadPolicy;

import com.jdy.cloud.security.StorageCryptoService;
import com.jdy.cloud.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import java.util.List;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;
import java.util.Set;

import java.util.Map;

import java.util.LinkedHashMap;

@Slf4j
@Service
@RequiredArgsConstructor
public class FileService {

    private final AuditLogService auditLogService;
    private final FileRepository fileRepository;
    private final FolderRepository folderRepository;
    private final UserRepository userRepository;
    private final ShareRepository shareRepository;
    private final PlatformTransactionManager transactionManager;
    private final FileContentSafetyService contentSafety;
    private final StorageCryptoService storageCrypto;

    @Value("${app.storage.upload-dir:${UPLOAD_DIR:./uploads}}")
    private String uploadDir;

    // IronWall v1.46.0: 白名单/黑名单统一由 UploadPolicy 提供（check/upload/merge 单一策略源）。
    private static final Set<String> ALLOWED_EXTENSIONS = UploadPolicy.NORMAL_USER_ALLOWED_EXTENSIONS;

    // IronWall v1.10: concurrent upload stability rework.
    // Old flow inserted the files child row first (FK takes a shared lock on the users row),
    // then updated the users row (exclusive lock) with a read-modify-write counter -> deadlocks
    // and lost updates under concurrency (5 concurrent uploads: 3x500). New flow:
    // 1) validation + disk write happen OUTSIDE any DB transaction;
    // 2) a short transaction runs inside a per-user lock and orders atomic UPDATE users (X lock)
    // -> INSERT files, which cannot deadlock;
    // 3) quota is enforced by a conditional atomic UPDATE (no race, no over-commit);
    // 4) the audit log is written after commit so audit-table FK locks never join the lock order.
    // IronWall v1.28.3: 管理员无视单文件大小限制与存储配额
    private boolean isAdmin(User user) {
        return user != null && "admin".equalsIgnoreCase(user.getRole());
    }

    public FileUploadResult uploadFile(Long userId, MultipartFile file, Long folderId) throws IOException {
        return uploadFile(userId, file, folderId, null);
    }

    /**
     * IronWall v1.45.0: expectedFileHash 为前端 X-Api-File-Hash（全文件 SHA-256，
     * 已由 ApiCryptoFilter 强制要求并纳入 HMAC 绑定）；落盘后对整文件重算 SHA-256 复核，
     * 缺失/空白/不匹配一律删除文件并拒绝，消除 v1.44.1 首尾 64KB 部分哈希的中间篡改盲区。
     */
    public FileUploadResult uploadFile(Long userId, MultipartFile file, Long folderId, String expectedFileHash) throws IOException {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));

        String originalName = file.getOriginalFilename();
        if (!SecurityUtils.isValidFilename(originalName)) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "invalid filename");
        }

        // IronWall v1.3: reject 0-byte files
        if (file.isEmpty() || file.getSize() <= 0) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "\u6587\u4ef6\u4e0d\u80fd\u4e3a\u7a7a");
        }

        // IronWall v1.3: folder id must not be negative
        if (folderId != null && folderId < 0) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "\u6587\u4ef6\u5939ID\u4e0d\u80fd\u4e3a\u8d1f\u6570");
        }

        // IronWall v1.46.0: 文件名/尺寸统一走 UploadPolicy（check/upload/merge 单一策略源）。
        // 直传超 10MB 普通用户明确拒绝并提示走分片，管理员豁免。
        UploadPolicy.validateFilename(originalName, isAdmin(user));
        UploadPolicy.validateSize(file.getSize(), isAdmin(user), true);
        String ext = UploadPolicy.extensionOf(originalName);

        if (!isAdmin(user)) {
            // IronWall v1.43.0: 单文件上限与存储配额统一——有效上限取 min(传输上限, 用户配额)，
            // 杜绝「配额 300MB 却可上传 850MB 单文件」的配置不一致（超配额终将被拒，提前拦截）。
            long storageCap = user.getStorageLimit() != null && user.getStorageLimit() > 0
                    ? user.getStorageLimit() : MAX_UPLOAD_BYTES;
            if (file.getSize() > storageCap) {
                // 文件本身超过用户配额总量，按配额不足处置（与历史语义一致）。
                throw new BusinessException(ErrorCode.STORAGE_FULL);
            }
        }

        // Advisory pre-check against the file table (fast, accurate message); the authoritative
        // guard is the conditional atomic UPDATE inside the transaction below.
        long currentSize = fileRepository.sumFileSizeByUserIdAndStatus(userId, 1);
        if (!isAdmin(user) && currentSize + file.getSize() > user.getStorageLimit()) {
            throw new BusinessException(ErrorCode.STORAGE_FULL);
        }

        if (folderId != null && folderId > 0) {
            Folder targetFolder = folderRepository.findById(folderId)
                    .orElseThrow(() -> new BusinessException(ErrorCode.FOLDER_NOT_FOUND));
            if (!targetFolder.getUserId().equals(userId)) {
                throw new BusinessException(ErrorCode.FOLDER_NOT_FOUND);
            }
        }

        String storedName = UUID.randomUUID().toString().replace("-", "") + (ext.isEmpty() ? "" : "." + ext);

        Path uploadPath = Path.of(uploadDir).toAbsolutePath().normalize();
        Files.createDirectories(uploadPath);
        Path targetPath = uploadPath.resolve(storedName).normalize();
        if (!targetPath.startsWith(uploadPath)) {
            throw new BusinessException(ErrorCode.INTERNAL_ERROR.getCode(), "invalid file path");
        }
        // IronWall v1.42.0: 落盘即静态加密（主密钥不可用时自动明文降级，上传不中断）
        try (java.io.OutputStream out = storageCrypto.openWrite(targetPath, file.getSize())) {
            file.getInputStream().transferTo(out);
        }

        // Hash from the file on disk (streamed) so the multipart stream can be consumed by transferTo safely.
        String fileHash = hashFile(targetPath);

        // IronWall v1.45.0: 全文件 SHA-256 强制完整性复核——
        // 头缺失/空白一律拒绝（防整体跳过校验）；整文件哈希不匹配即删文件拒绝，
        // 消除 v1.44.1 首尾 64KB 部分哈希的中间内容篡改盲区。
        if (expectedFileHash == null || !expectedFileHash.matches("[0-9a-fA-F]{64}")) {
            Files.deleteIfExists(targetPath);
            log.warn("[IronWall] multipart missing/invalid file hash: userId={} size={} path={}",
                    userId, file.getSize(), targetPath.getFileName());
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "缺少文件完整性哈希，请刷新页面后重试");
        }
        boolean match = MessageDigest.isEqual(
                fileHash.getBytes(StandardCharsets.UTF_8),
                expectedFileHash.trim().toLowerCase(java.util.Locale.ROOT).getBytes(StandardCharsets.UTF_8));
        if (!match) {
            Files.deleteIfExists(targetPath);
            log.warn("[IronWall] multipart integrity mismatch: userId={} size={} path={}",
                    userId, file.getSize(), targetPath.getFileName());
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "上传内容完整性校验失败，请重新上传");
        }

        // IronWall v1.28.4: 文件内容安全体检（可执行/脚本/伪装/病毒），管理员同样强制体检
        FileContentSafetyService.ScanResult scanResult = contentSafety.scan(targetPath, originalName, isAdmin(user));
        if (!scanResult.safe()) {
            Files.deleteIfExists(targetPath);
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), scanResult.reason());
        }

        String mimeType = file.getContentType();
        if (mimeType == null) {
            mimeType = "application/octet-stream";
        } else if (mimeType.contains(";") || mimeType.length() > 200) {
            Files.deleteIfExists(targetPath);
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "invalid mime type");
        }
        String fileType = mimeType.split("/")[0];

        FileEntity entity = new FileEntity();
        entity.setFilename(storedName);
        entity.setOriginalName(originalName != null ? originalName : "unknown");
        entity.setFileSize(file.getSize());
        entity.setFileType(fileType);
        entity.setMimeType(mimeType);
        entity.setFileHash(fileHash);
        entity.setUserId(userId);
        entity.setFolderId(folderId != null ? folderId : 0L);

        final FileEntity[] savedHolder = new FileEntity[1];
        synchronized (uploadLockFor(userId)) {
            try {
                savedHolder[0] = new TransactionTemplate(transactionManager).execute(status -> {
                    boolean adminUpload = isAdmin(user);
                    int updated = adminUpload
                            ? userRepository.incrementStorageUsed(userId, file.getSize())
                            : userRepository.incrementStorageUsedWithinLimit(userId, file.getSize());
                    if (updated == 0 && !adminUpload) {
                        throw new BusinessException(ErrorCode.STORAGE_FULL);
                    }
                    return fileRepository.save(entity);
                });
            } catch (RuntimeException e) {
                try {
                    Files.deleteIfExists(targetPath);
                } catch (IOException cleanupError) {
                    log.warn("upload cleanup failed: {}", cleanupError.getMessage());
                }
                throw e;
            }
        }
        FileEntity saved = savedHolder[0];

        // Audit after commit: keeps audit-table FK locks out of the transaction lock order.
        auditLogService.logUpload(userId, originalName, file.getSize(), "system");

        return new FileUploadResult(
                saved.getId(), saved.getFilename(), saved.getOriginalName(),
                saved.getFileSize(), saved.getFileType(), saved.getMimeType(),
                saved.getFolderId(), saved.getDownloadCount(),
                saved.getCreatedAt().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
        );
    }

    private static final Object[] UPLOAD_LOCKS = new Object[64];
    static {
        for (int i = 0; i < UPLOAD_LOCKS.length; i++) {
            UPLOAD_LOCKS[i] = new Object();
        }
    }

    private Object uploadLockFor(Long userId) {
        long id = userId == null ? 0L : userId;
        return UPLOAD_LOCKS[(int) (Math.floorMod(id, UPLOAD_LOCKS.length))];
    }

    private String hashFile(Path path) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            // IronWall v1.42.0: 哈希在明文层计算（加密文件透明解密）
            try (InputStream in = storageCrypto.openRead(path)) {
                byte[] buffer = new byte[8192];
                int n;
                while ((n = in.read(buffer)) > 0) {
                    md.update(buffer, 0, n);
                }
            }
            return bytesToHex(md.digest());
        } catch (Exception e) {
            log.warn("Failed to compute file hash", e);
            return "";
        }
    }

    public Page<FileEntity> listFiles(Long userId, Long folderId, int page, int size) {
        log.info("listFiles called: userId={}, folderId={}, page={}, size={}", userId, folderId, page, size);
        if (folderId != null && folderId < 0) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "文件夹ID不能为负数");
        }
        if (page < 0 || size < 1 || size > 100) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "分页参数无效");
        }
        PageRequest pageable = PageRequest.of(page, size);
        if (folderId != null && folderId > 0) {
            return fileRepository.findByUserIdAndFolderIdAndStatus(userId, folderId, 1, pageable);
        }
        // Root level: only return files with folder_id = 0
        return fileRepository.findByUserIdAndFolderIdAndStatus(userId, 0L, 1, pageable);
    }

    public java.util.Map<String, Object> getStorageStats(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));

        // IronWall v1.47.3: 展示口径改为 files 表实算（自愈历史漂移），配额扣减逻辑不受影响
        long used = fileRepository.sumFileSizeByUserIdAndStatus(userId, 1);
        long totalDownloads = fileRepository.sumDownloadCountByUserIdAndStatus(userId, 1);

        return java.util.Map.of(
                "used", used,
                "limit", user.getStorageLimit(),
                "upload_limit", user.getUploadLimit(),
                "total_downloads", totalDownloads
        );
    }

    @Transactional
    public void deleteFile(Long userId, Long fileId) {
        FileEntity file = fileRepository.findById(fileId)
                .orElseThrow(() -> new BusinessException(ErrorCode.FILE_NOT_FOUND));
        if (!file.getUserId().equals(userId)) {
            throw new BusinessException(ErrorCode.FORBIDDEN);
        }
        // IronWall v1.13: idempotent guard - files already in the recycle bin must not double-decrement quota
        if (file.getStatus() != 1) {
            return;
        }
        file.setStatus(0);
        fileRepository.save(file);
        if (file.getFileSize() != null && file.getFileSize() > 0) {
            userRepository.incrementStorageUsed(userId, -file.getFileSize());
        }
        auditLogService.logDeleteFile(userId, file.getOriginalName(), "system", false);
    }

    @Transactional
    public void restoreFile(Long userId, Long fileId) {
        FileEntity file = fileRepository.findById(fileId)
                .orElseThrow(() -> new BusinessException(ErrorCode.FILE_NOT_FOUND));
        if (!file.getUserId().equals(userId)) {
            throw new BusinessException(ErrorCode.FORBIDDEN);
        }
        // IronWall v1.13: only recycle-bin files can be restored; idempotent for active files
        if (file.getStatus() != 0) {
            return;
        }
        // enforce quota atomically BEFORE restoring so "delete -> upload -> restore" can never bypass the limit
        if (file.getFileSize() != null && file.getFileSize() > 0) {
            int quotaUpdated = userRepository.incrementStorageUsedWithinLimit(userId, file.getFileSize());
            if (quotaUpdated == 0) {
                throw new BusinessException(ErrorCode.STORAGE_FULL);
            }
        }
        file.setStatus(1);
        // If parent folder no longer exists, move file to root
        if (file.getFolderId() != null && file.getFolderId() > 0) {
            if (!folderRepository.existsById(file.getFolderId())) {
                file.setFolderId(0L);
            }
        }
        fileRepository.save(file);
        auditLogService.logRestoreFile(userId, file.getOriginalName(), "system");
    }

    @Transactional
    public void permanentDeleteFile(Long userId, Long fileId) {
        FileEntity file = fileRepository.findById(fileId)
                .orElseThrow(() -> new BusinessException(ErrorCode.FILE_NOT_FOUND));
        if (!file.getUserId().equals(userId)) {
            throw new BusinessException(ErrorCode.FORBIDDEN);
        }
        // IronWall v1.13: active files must go to the recycle bin first (soft delete decrements
        // the quota counter); permanently deleting an active file would orphan the counter
        if (file.getStatus() == 1) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "\u8bf7\u5148\u5c06\u6587\u4ef6\u79fb\u5165\u56de\u6536\u7ad9\u518d\u5f7b\u5e95\u5220\u9664");
        }
        // IronWall v1.19: 存在分享外键引用时返回 409 而非数据库异常 500
        if (shareRepository.existsByFileId(fileId)) {
            throw new BusinessException(ErrorCode.CONFLICT.getCode(), "文件存在分享引用，请先取消相关分享");
        }
        String permFileName = file.getOriginalName();
        try {
            fileRepository.delete(file);
            fileRepository.flush();
        } catch (DataIntegrityViolationException e) {
            throw new BusinessException(ErrorCode.CONFLICT.getCode(), "文件存在分享引用，请先取消相关分享");
        }
        try {
            Path uploadPath = Path.of(uploadDir).toAbsolutePath().normalize();
            Path filePath = uploadPath.resolve(file.getFilename()).normalize();
            if (filePath.startsWith(uploadPath)) {
                Files.deleteIfExists(filePath);
            }
        } catch (IOException e) {
            log.warn("Failed to delete physical file: {}", file.getFilename());
        }
        auditLogService.logDeleteFile(userId, permFileName, "system", true);
    }

    public Page<FileEntity> getDeletedFiles(Long userId, int page, int size) {
        if (page < 0 || size < 1 || size > 100) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "分页参数无效");
        }
        return fileRepository.findByUserIdAndStatus(userId, 0, PageRequest.of(page, size));
    }

    // IronWall v1.3: 下载归属校验 + 空安全计数
    public FileEntity getFileForDownload(Long userId, Long fileId) {
        FileEntity file = fileRepository.findById(fileId)
                .orElseThrow(() -> new BusinessException(ErrorCode.FILE_NOT_FOUND));
        if (!file.getUserId().equals(userId)) {
            throw new BusinessException(ErrorCode.FILE_NOT_FOUND);
        }
        if (file.getStatus() != 1) {
            throw new BusinessException(ErrorCode.FILE_NOT_FOUND);
        }
        int count = file.getDownloadCount() == null ? 0 : file.getDownloadCount();
        file.setDownloadCount(count + 1);
        fileRepository.save(file);
        return file;
    }

    @Transactional
    public Folder createFolder(Long userId, String name, Long parentId) {
        if (name == null || name.trim().isEmpty()) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "文件夹名称不能为空");
        }
        String safeName = SecurityUtils.stripHtmlTags(name.trim());
        if (safeName.isEmpty() || safeName.length() > 50) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "文件夹名称无效（长度1-50）");
        }
        if (parentId != null && parentId < 0) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "父文件夹ID不能为负数");
        }
        if (parentId != null && parentId > 0) {
            Folder parent = folderRepository.findById(parentId)
                    .orElseThrow(() -> new BusinessException(ErrorCode.FOLDER_NOT_FOUND));
            if (!parent.getUserId().equals(userId)) {
                throw new BusinessException(ErrorCode.FOLDER_NOT_FOUND);
            }
            if (folderRepository.existsByParentIdAndNameAndStatus(parentId, safeName, 1)) {
                throw new BusinessException(ErrorCode.CONFLICT.getCode(), "folder with same name already exists");
            }
        }

        Folder folder = new Folder();
        folder.setUserId(userId);
        folder.setName(safeName);
        folder.setParentId(parentId != null ? parentId : 0L);
        Folder saved = folderRepository.save(folder);
        auditLogService.logCreateFolder(userId, safeName, "system");
        return saved;
    }

    public java.util.List<Folder> listFolders(Long userId, Long parentId) {
        if (parentId != null && parentId < 0) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "父文件夹ID不能为负数");
        }
        return folderRepository.findByUserIdAndParentIdAndStatus(userId,
                parentId != null ? parentId : 0L, 1);
    }

    @Transactional
    public void deleteFolder(Long userId, Long folderId) {
        Folder folder = folderRepository.findById(folderId)
                .orElseThrow(() -> new BusinessException(ErrorCode.FOLDER_NOT_FOUND));

        if (!folder.getUserId().equals(userId)) {
            throw new BusinessException(ErrorCode.FORBIDDEN);
        }

        // Recursively delete sub-folders first
        List<Folder> subFolders = folderRepository.findByParentIdAndStatus(folderId, 1);
        for (Folder sub : subFolders) {
            deleteFolder(userId, sub.getId());
        }

        // Soft-delete all files in this folder (set status to 0)
        List<FileEntity> files = fileRepository.findByFolderIdAndStatus(folderId, 1);
        long deletedSize = 0;
        for (FileEntity f : files) {
            f.setStatus(0);
            deletedSize += f.getFileSize() != null ? f.getFileSize() : 0;
            fileRepository.save(f);
        }

        // IronWall v1.13: atomic quota decrement (no read-modify-write race)
        if (deletedSize > 0) {
            userRepository.incrementStorageUsed(userId, -deletedSize);
        }

        // Delete the folder
        folderRepository.delete(folder);
        auditLogService.logDeleteFolder(userId, folder.getName(), "system");
        log.info("Folder deleted: id={} name={} (including {} files, {} sub-folders, freed {} bytes)",
                folderId, folder.getName(), files.size(), subFolders.size(), deletedSize);
    }

    // ================= IronWall v1.28.0: 秒传 + 分片续传 =================
    // IronWall v1.46.0: 阈值统一由 UploadPolicy 提供（site/info 下发同源数值）。

    private static final long CHUNK_MAX_BYTES = UploadPolicy.CHUNK_SIZE_BYTES;

    // IronWall v1.28.3: 单文件上传上限 850MB（普通用户同时受 300MB 存储配额约束，管理员无视限制）
    private static final long MAX_UPLOAD_BYTES = UploadPolicy.MAX_FILE_BYTES;
    private static final long CHUNK_TOTAL_LIMIT = MAX_UPLOAD_BYTES;
    // IronWall v1.28.3: 管理员无视单文件上限，仅保留 20GB 安全阀防止异常声明撑爆磁盘
    private static final long ADMIN_CHUNK_TOTAL_LIMIT = UploadPolicy.ADMIN_MAX_FILE_BYTES;
    private static final int ADMIN_CHUNK_MAX_COUNT = 2000;
    // IronWall v1.28.1: 分片数上限 = 单文件上限 / 分片大小，防止攻击者声明超大 total 写入海量临时分片撑爆磁盘
    private static final int CHUNK_MAX_COUNT = (int) (CHUNK_TOTAL_LIMIT / CHUNK_MAX_BYTES);

    private static final java.util.regex.Pattern SHA256_RE = java.util.regex.Pattern.compile("[0-9a-f]{64}");

    /** 上传前检查：秒传命中 / 已上传分片列表。 */

    public Map<String, Object> checkUpload(Long userId, String filename, Long size, String sha256) {

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        validateUploadMeta(filename, size, isAdmin(user));

        if (sha256 == null || !SHA256_RE.matcher(sha256).matches()) {

            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "文件指纹无效，请重新上传");

        }

        Map<String, Object> result = new LinkedHashMap<>();

        result.put("exists", false);

        // IronWall v1.46.0: 下发策略版本与分片大小，前端按服务端配置分流。
        result.put("policy_version", UploadPolicy.POLICY_VERSION);
        result.put("chunk_size_bytes", UploadPolicy.CHUNK_SIZE_BYTES);

        java.util.Optional<FileEntity> source = fileRepository

                .findFirstByFileHashAndFileSizeAndStatusOrderByIdAsc(sha256, size, 1);

        Path uploadPath = Path.of(uploadDir).toAbsolutePath().normalize();

        if (source.isPresent()) {

            Path physical = uploadPath.resolve(source.get().getFilename()).normalize();

            if (physical.startsWith(uploadPath) && Files.exists(physical)) {

                result.put("exists", true);

                result.put("file_id", source.get().getId());

                result.put("uploaded_chunks", java.util.Collections.emptyList());

                return result;

            }

        }

        result.put("uploaded_chunks", uploadedChunkIndexes(userId, sha256));

        return result;

    }

    /**
     * 保存单个分片到临时目录。
     * IronWall v1.45.0: expectedChunkHash 为 X-Api-Chunk-Hash（HMAC 已绑定），
     * 分片落盘后按明文层重算 SHA-256 比对，不匹配即删除临时分片并拒绝。
     */
    public int saveChunk(Long userId, String sha256, int index, int total, MultipartFile chunk, String expectedChunkHash) {

        if (sha256 == null || !SHA256_RE.matcher(sha256).matches()) {

            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "文件指纹无效");

        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        int maxCount = isAdmin(user) ? ADMIN_CHUNK_MAX_COUNT : CHUNK_MAX_COUNT;
        if (index < 0 || total < 1 || index >= total || total > maxCount) {

            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "分片参数无效");

        }

        if (chunk == null || chunk.isEmpty() || chunk.getSize() <= 0 || chunk.getSize() > CHUNK_MAX_BYTES) {

            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "分片大小无效");

        }

        try {

            Path uploadPath = Path.of(uploadDir).toAbsolutePath().normalize();

            Path chunkDir = chunkDirFor(uploadPath, userId, sha256);

            Files.createDirectories(chunkDir);

            Path part = chunkDir.resolve(index + ".part");

            Path tmp = chunkDir.resolve(index + ".tmp");

            // IronWall v1.42.0: 分片同样落盘即加密
            try (java.io.OutputStream out = storageCrypto.openWrite(tmp, chunk.getSize())) {
                chunk.getInputStream().transferTo(out);
            }

            // IronWall v1.45.0: 分片级完整性复核（明文层重算 SHA-256 与 X-Api-Chunk-Hash 比对）
            if (expectedChunkHash == null || !expectedChunkHash.matches("[0-9a-fA-F]{64}")) {
                Files.deleteIfExists(tmp);
                log.warn("[IronWall] chunk missing/invalid hash: userId={} index={}", userId, index);
                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "缺少分片完整性哈希，请刷新页面后重试");
            }
            String actualChunkHash = hashFile(tmp);
            if (!MessageDigest.isEqual(
                    actualChunkHash.getBytes(StandardCharsets.UTF_8),
                    expectedChunkHash.trim().toLowerCase(java.util.Locale.ROOT).getBytes(StandardCharsets.UTF_8))) {
                Files.deleteIfExists(tmp);
                log.warn("[IronWall] chunk integrity mismatch: userId={} index={}", userId, index);
                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "分片完整性校验失败，请重试");
            }

            Files.move(tmp, part, java.nio.file.StandardCopyOption.REPLACE_EXISTING,

                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);

            return index;

        } catch (IOException e) {

            log.warn("saveChunk failed: {}", e.getMessage());

            throw new BusinessException(ErrorCode.FILE_UPLOAD_FAILED.getCode(), "分片保存失败，请重试");

        }

    }

    /** 合并分片（或 total=0 时直接秒传登记），校验 SHA-256 后落库。 */

    public FileUploadResult mergeChunks(Long userId, String sha256, String filename, Long size,

                                        int total, Long folderId, String mimeType) {

        User uploadUser = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        validateUploadMeta(filename, size, isAdmin(uploadUser));

        if (sha256 == null || !SHA256_RE.matcher(sha256).matches()) {

            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "文件指纹无效");

        }

        Path uploadPath = Path.of(uploadDir).toAbsolutePath().normalize();

        try {

            Files.createDirectories(uploadPath);

        } catch (IOException e) {

            throw new BusinessException(ErrorCode.FILE_UPLOAD_FAILED.getCode(), "存储目录不可用");

        }

        String storedName;

        if (total == 0) {

            // 秒传：复用已有物理文件

            java.util.Optional<FileEntity> source = fileRepository

                    .findFirstByFileHashAndFileSizeAndStatusOrderByIdAsc(sha256, size, 1);

            if (source.isEmpty()) {

                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "秒传源文件已失效，请重新上传");

            }

            storedName = source.get().getFilename();

            Path physical = uploadPath.resolve(storedName).normalize();

            if (!physical.startsWith(uploadPath) || !Files.exists(physical)) {

                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "秒传源文件已失效，请重新上传");

            }

        } else {

            if (total < 1 || total > (isAdmin(uploadUser) ? ADMIN_CHUNK_MAX_COUNT : CHUNK_MAX_COUNT)) {

                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "分片参数无效");

            }

            Path chunkDir = chunkDirFor(uploadPath, userId, sha256);

            long sum = 0;

            for (int i = 0; i < total; i++) {

                Path part = chunkDir.resolve(i + ".part");

                if (!Files.exists(part)) {

                    throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "缺少分片 " + i + "，请重传");

                }

                // IronWall v1.42.0: 加密分片用明文长度参与尺寸校验（内部容错，不抛检查异常）
                sum += storageCrypto.plainLength(part);

            }

            if (sum != size) {

                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "分片大小与文件大小不一致，请重新上传");

            }

            // 合并并顺带计算 SHA-256，与客户端指纹比对（防指纹伪造）

            String ext = extensionOf(filename);

            String mergedName = "tmp-" + UUID.randomUUID().toString().replace("-", "") + (ext.isEmpty() ? "" : "." + ext);

            Path merged = uploadPath.resolve(mergedName).normalize();

            try {

                MessageDigest md = MessageDigest.getInstance("SHA-256");

                long mergedSize = size == null ? 0L : size;
                try (java.io.OutputStream out = storageCrypto.openWrite(merged, mergedSize)) {

                    byte[] buffer = new byte[8192];

                    for (int i = 0; i < total; i++) {

                        try (InputStream in = storageCrypto.openRead(chunkDir.resolve(i + ".part"))) {

                            int n;

                            while ((n = in.read(buffer)) > 0) {

                                md.update(buffer, 0, n);

                                out.write(buffer, 0, n);

                            }

                        }

                    }

                }

                String actual = bytesToHex(md.digest());

                if (!actual.equalsIgnoreCase(sha256)) {

                    Files.deleteIfExists(merged);

                    throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "文件校验失败，请重新上传");

                }

            }

                catch (Exception e) {

                    try { Files.deleteIfExists(merged); } catch (IOException ignored) { }

                throw new BusinessException(ErrorCode.FILE_UPLOAD_FAILED.getCode(), "分片合并失败，请重试");

            }

            storedName = merged.getFileName().toString();

            deleteChunkDir(chunkDir);

        }

        // IronWall v1.28.4: 合并/秒传后对物理文件做内容体检（防改名伪装与病毒）
        Path physicalForScan = uploadPath.resolve(storedName).normalize();
        FileContentSafetyService.ScanResult scanResult = contentSafety.scan(physicalForScan, filename, isAdmin(uploadUser));
        if (!scanResult.safe()) {

            if (total != 0) {
                try { Files.deleteIfExists(physicalForScan); } catch (IOException ignored) { }
            }
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), scanResult.reason());

        }

        String safeMime = mimeType == null || mimeType.isBlank() || mimeType.length() > 200 || mimeType.contains(";")

                ? "application/octet-stream" : mimeType;

        String fileType = safeMime.split("/")[0];

        FileEntity saved = registerFile(userId, storedName, filename, size, safeMime, fileType, sha256, folderId);

        auditLogService.logUpload(userId, filename, size, "system");

        return new FileUploadResult(

                saved.getId(), saved.getFilename(), saved.getOriginalName(),

                saved.getFileSize(), saved.getFileType(), saved.getMimeType(),

                saved.getFolderId(), saved.getDownloadCount(),

                saved.getCreatedAt().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)

        );

    }

    /** 共用登记逻辑：配额原子扣减 + 落库（与 uploadFile 相同锁序，避免死锁）。 */

    private FileEntity registerFile(Long userId, String storedName, String originalName, Long size,

                                    String mimeType, String fileType, String fileHash, Long folderId) {

        User user = userRepository.findById(userId)

                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));

        long currentSize = fileRepository.sumFileSizeByUserIdAndStatus(userId, 1);

        if (!isAdmin(user) && currentSize + size > user.getStorageLimit()) {

            throw new BusinessException(ErrorCode.STORAGE_FULL);

        }

        if (folderId != null && folderId > 0) {

            Folder targetFolder = folderRepository.findById(folderId)

                    .orElseThrow(() -> new BusinessException(ErrorCode.FOLDER_NOT_FOUND));

            if (!targetFolder.getUserId().equals(userId)) {

                throw new BusinessException(ErrorCode.FOLDER_NOT_FOUND);

            }

        }

        FileEntity entity = new FileEntity();

        entity.setFilename(storedName);

        entity.setOriginalName(originalName != null ? originalName : "unknown");

        entity.setFileSize(size);

        entity.setFileType(fileType);

        entity.setMimeType(mimeType);

        entity.setFileHash(fileHash);

        entity.setUserId(userId);

        entity.setFolderId(folderId != null ? folderId : 0L);

        synchronized (uploadLockFor(userId)) {

            return new TransactionTemplate(transactionManager).execute(status -> {

                boolean adminUpload = isAdmin(user);
                int updated = adminUpload
                        ? userRepository.incrementStorageUsed(userId, size)
                        : userRepository.incrementStorageUsedWithinLimit(userId, size);
                if (updated == 0 && !adminUpload) {

                    throw new BusinessException(ErrorCode.STORAGE_FULL);

                }

                return fileRepository.save(entity);

            });

        }

    }

    private void validateUploadMeta(String filename, Long size, boolean admin) {
        // IronWall v1.46.0: check/merge 与直传共用 UploadPolicy 单一策略源，
        // 双扩展走私（.html.txt/.php.jpg）与尺寸阈值三处结论一致。
        UploadPolicy.validateFilename(filename, admin);
        UploadPolicy.validateSize(size == null ? 0L : size, admin, false);
    }

    private String extensionOf(String filename) {
        // IronWall v1.46.0: 统一委托 UploadPolicy，避免派生逻辑漂移。
        return UploadPolicy.extensionOf(filename);
    }

    private Path chunkDirFor(Path uploadPath, Long userId, String sha256) {

        return uploadPath.resolve(".chunks").resolve(String.valueOf(userId)).resolve(sha256).normalize();

    }

    private java.util.List<Integer> uploadedChunkIndexes(Long userId, String sha256) {

        java.util.List<Integer> indexes = new java.util.ArrayList<>();

        try {

            Path chunkDir = chunkDirFor(Path.of(uploadDir).toAbsolutePath().normalize(), userId, sha256);

            if (Files.isDirectory(chunkDir)) {

                try (java.util.stream.Stream<Path> stream = Files.list(chunkDir)) {

                    stream.filter(p -> p.getFileName().toString().endsWith(".part"))

                            .forEach(p -> {

                                String name = p.getFileName().toString();

                                try {

                                    indexes.add(Integer.parseInt(name.substring(0, name.length() - 5)));

                                } catch (NumberFormatException ignored) { }

                            });

                }

            }

        } catch (IOException e) {

            log.warn("uploadedChunkIndexes scan failed: {}", e.getMessage());

        }

        return indexes;

    }

    private void deleteChunkDir(Path chunkDir) {

        try {

            if (Files.isDirectory(chunkDir)) {

                try (java.util.stream.Stream<Path> stream = Files.list(chunkDir)) {

                    stream.forEach(p -> {

                        try { Files.deleteIfExists(p); } catch (IOException ignored) { }

                    });

                }

                Files.deleteIfExists(chunkDir);

            }

        } catch (IOException e) {

            log.warn("deleteChunkDir failed: {}", e.getMessage());

        }

    }

    /** 清理超过 24 小时的孤儿分片目录（由回收站定时任务调用）。 */

    public int cleanupOrphanChunks() {

        int removed = 0;

        try {

            Path chunksRoot = Path.of(uploadDir).toAbsolutePath().normalize().resolve(".chunks");

            if (!Files.isDirectory(chunksRoot)) return 0;

            long cutoff = System.currentTimeMillis() - 24 * 3600_000L;

            try (java.util.stream.Stream<Path> users = Files.list(chunksRoot)) {

                for (Path userDir : users.toList()) {

                    if (!Files.isDirectory(userDir)) continue;

                    try (java.util.stream.Stream<Path> hashes = Files.list(userDir)) {

                        for (Path hashDir : hashes.toList()) {

                            if (!Files.isDirectory(hashDir)) continue;

                            if (Files.getLastModifiedTime(hashDir).toMillis() < cutoff) {

                                deleteChunkDir(hashDir);

                                removed++;

                            }

                        }

                    }

                }

            }

        } catch (IOException e) {

            log.warn("cleanupOrphanChunks failed: {}", e.getMessage());

        }

        return removed;

    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
