package com.jdy.cloud.service;

import com.jdy.cloud.dto.CreateShareRequest;
import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.ErrorCode;
import com.jdy.cloud.model.FileEntity;
import com.jdy.cloud.model.Folder;
import com.jdy.cloud.model.Share;
import com.jdy.cloud.repository.FileRepository;
import com.jdy.cloud.repository.UserRepository;
import com.jdy.cloud.repository.FolderRepository;
import com.jdy.cloud.repository.ShareRepository;
import com.jdy.cloud.security.ShareLinkSigner;
import com.jdy.cloud.security.StorageCryptoService;
import com.jdy.cloud.util.SecurityUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@Slf4j
@Service
@RequiredArgsConstructor
public class ShareService {

    private final ShareRepository shareRepository;
    private final FileRepository fileRepository;
    private final UserRepository userRepository;
    private final AuditLogService auditLogService;
    private final ShareLinkSigner shareLinkSigner;
    private final StorageCryptoService storageCrypto;
    @Autowired
    private PasswordGuardService passwordGuardService;
    private final FolderRepository folderRepository;

    @Value("${app.storage.upload-dir:./uploads}")
    private String uploadDir;

    // IronWall v1.47.9: 分享打包下载资源上限（防压缩炸弹 / 超大分享拖垮服务）
    @Value("${app.security.share-zip.max-entries:1000}")
    private int shareZipMaxEntries;

    @Value("${app.security.share-zip.max-total-bytes:314572800}")
    private long shareZipMaxTotalBytes;

    public Page<Share> listShares(Long userId, int page, int size) {
        return shareRepository.findByUserIdOrderByCreatedAtDesc(userId, PageRequest.of(page, size));
    }

    @Transactional
    public Share createShare(Long userId, CreateShareRequest request) {
        log.info("createShare: userId={} fileId={} folderId={} days={} pwLen={}",
                userId, request.getFileId(), request.getFolderId(), request.getDays(),
                request.getPassword() != null ? request.getPassword().length() : 0);
        try {
            if (request.getFileId() == null && request.getFolderId() == null) {
                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "文件ID或文件夹ID不能为空");
            }
            if (request.getFileId() != null && request.getFileId() <= 0) {
                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "文件ID无效");
            }
            if (request.getFolderId() != null && request.getFolderId() <= 0) {
                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "文件夹ID无效");
            }

            Share share = new Share();
            share.setUserId(userId);

            if (request.getFileId() != null) {
                FileEntity file = fileRepository.findById(request.getFileId())
                        .orElseThrow(() -> new BusinessException(ErrorCode.FILE_NOT_FOUND));
                if (!file.getUserId().equals(userId)) {
                    throw new BusinessException(ErrorCode.FORBIDDEN);
                }
                share.setFileId(request.getFileId());
                share.setShareType(1);
            } else {
                Folder folder = folderRepository.findById(request.getFolderId())
                        .orElseThrow(() -> new BusinessException(ErrorCode.FOLDER_NOT_FOUND));
                if (!folder.getUserId().equals(userId)) {
                    throw new BusinessException(ErrorCode.FORBIDDEN);
                }
                share.setFolderId(request.getFolderId());
                share.setShareType(2);
            }

            // IronWall v1.43.0: 分享码熵值 32bit -> 80bit（20 位十六进制，列长上限内），
            // 配合查询/下载限流，枚举面从 42 亿级提升到 1.2e24，实际不可穷举。
            share.setShareCode(UUID.randomUUID().toString().replace("-", "").substring(0, 20).toLowerCase(java.util.Locale.ROOT));
            share.setDownloadLimit(request.getDownloadLimit() > 0 ? request.getDownloadLimit() : -1);
            if (request.getPassword() != null && !request.getPassword().isEmpty()) {
                // IronWall v1.19: 数据库列宽为 10，前后端统一 4~10 位，超长返回 400 而非 500
                int passwordLength = request.getPassword().length();
                if (passwordLength < 4 || passwordLength > 10) {
                    throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "分享密码长度需为4-10位");
                }
                // IronWall v1.28.9: 只存加盐哈希，服务端不保留明文密码
                share.setPassword(PasswordGuardService.hashSharePassword(share.getShareCode(), request.getPassword()));
            }
            // IronWall v1.3: 文本字段剥离 HTML 与控制字符
            if (request.getDescription() != null && !request.getDescription().isEmpty()) {
                share.setDescription(SecurityUtils.stripHtmlTags(request.getDescription()));
            }
            if (request.getContact() != null && !request.getContact().isEmpty()) {
                share.setContact(SecurityUtils.stripHtmlTags(request.getContact()));
            }
            if (request.getSharerName() != null && !request.getSharerName().isEmpty()) {
                share.setSharerName(SecurityUtils.stripHtmlTags(request.getSharerName()));
            }
            // IronWall v1.3: 支持 days / expires_in / expireDays 三种过期参数
            int expireDays = resolveExpireDays(request);
            if (expireDays < 0) {
                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "过期时间参数无效");
            }
            if (expireDays > 0) {
                LocalDateTime expireAt = LocalDateTime.now().plusDays(Math.min(expireDays, 3650));
                share.setExpireTime(expireAt);
                share.setExpiresAt(expireAt);
            }
            Share saved = shareRepository.save(share);
            log.info("createShare: success shareId={} code={}", saved.getId(), saved.getShareCode());
            String shareFileName = "";
            if (saved.getFileId() != null) {
                shareFileName = fileRepository.findById(saved.getFileId()).map(f -> f.getOriginalName()).orElse("");
            }
            auditLogService.logCreateShare(userId, saved.getShareCode(), shareFileName, "system");
            return saved;
        } catch (BusinessException e) {
            throw e;
        } catch (Exception e) {
            log.error("createShare: unexpected error", e);
            throw new BusinessException(ErrorCode.INTERNAL_ERROR.getCode(), ErrorCode.INTERNAL_ERROR.getMessage());
        }
    }

    // IronWall v1.3: 过期参数优先级 days > expires_in > expireDays
    private int resolveExpireDays(CreateShareRequest request) {
        if (request.getDays() != 0) return request.getDays();
        if (request.getExpiresIn() != null) return request.getExpiresIn();
        if (request.getExpireDays() != null) return request.getExpireDays();
        return 0;
    }

    /**
     * IronWall v1.47.11: 公开分享下载审计。
     *
     * 下载者是匿名访客、不是分享者本人，因此不能再复用 logDownload(分享者ID, ...)——
     * 那会把访客动作记成分享者的站内下载。改用专用动作码 share_download，
     * 由 AuditLogService 统一写成「访客通过公开分享下载」的准确事实。
     */
    private void safeAuditShareDownload(Share share, String fileName) {
        try {
            auditLogService.logShareDownload(share.getUserId(), share.getShareCode(), fileName);
        } catch (Exception e) {
            log.warn("audit share download log failed: {}", e.getMessage());
        }
    }

    @Transactional
    public void deleteShare(Long userId, Long shareId) {
        Share share = shareRepository.findById(shareId)
                .orElseThrow(() -> new BusinessException(ErrorCode.SHARE_NOT_FOUND));
        if (!share.getUserId().equals(userId)) {
            throw new BusinessException(ErrorCode.FORBIDDEN);
        }
        String delCode = share.getShareCode();
        shareRepository.delete(share);
        auditLogService.logDeleteShare(userId, delCode, "system");
    }

    public Map<String, Object> getShareInfo(String code, String pwHash, String pwToken) {
        code = normalizeShareCode(code);
        Share share = shareRepository.findByShareCode(code)
                .orElseThrow(() -> new BusinessException(ErrorCode.NOT_FOUND));

        // 检查分享是否过期或已失效
        // IronWall v1.27.6: 封禁分享给出专属提示（-2 由管理员封禁，区别于过期/失效）
        if (Integer.valueOf(-2).equals(share.getStatus())) {
            throw new BusinessException(ErrorCode.SHARE_BANNED);
        }
        if (!Integer.valueOf(1).equals(share.getStatus())) {
            throw new BusinessException(ErrorCode.SHARE_EXPIRED);
        }
        if (share.getExpireTime() != null && share.getExpireTime().isBefore(LocalDateTime.now())) {
            share.setStatus(0);
            shareRepository.save(share);
            throw new BusinessException(ErrorCode.SHARE_EXPIRED);
        }

        if (share.getPassword() != null && !share.getPassword().isEmpty()) {
            // 密码护航安全引擎：优先使用挑战-应答验证
            if (pwHash != null && !pwHash.isEmpty() && pwToken != null && !pwToken.isEmpty()) {
                if (!passwordGuardService.verifyChallenge(code, pwToken, pwHash, share.getPassword())) {
                    throw new BusinessException(ErrorCode.SHARE_WRONG_PASSWORD);
                }
            }
            // IronWall v1.22.0: 明文密码路径已移除，未携带安全令牌仅返回最小信息
            // 无密码：返回最小信息
            else {
                Map<String, Object> pwResult = new LinkedHashMap<>();
                pwResult.put("id", share.getId());
                pwResult.put("share_code", share.getShareCode());
                pwResult.put("share_type", share.getShareType());
                pwResult.put("has_password", true);
                pwResult.put("status", share.getStatus());
                pwResult.put("contact", SecurityUtils.stripHtmlTags(share.getContact()));
                pwResult.put("sharer_name", SecurityUtils.stripHtmlTags(share.getSharerName()));
                pwResult.put("description", SecurityUtils.stripHtmlTags(share.getDescription()));
                return pwResult;
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", share.getId());
        result.put("share_code", share.getShareCode());
        result.put("share_type", share.getShareType());
        result.put("file_id", share.getFileId());
        result.put("folder_id", share.getFolderId());
        result.put("download_limit", share.getDownloadLimit());
        result.put("download_count", share.getDownloadCount());
        result.put("expire_time", share.getExpireTime() != null ? share.getExpireTime().toString() : null);
        result.put("has_password", share.getPassword() != null && !share.getPassword().isEmpty());
        result.put("description", SecurityUtils.stripHtmlTags(share.getDescription()));
        result.put("contact", SecurityUtils.stripHtmlTags(share.getContact()));
        result.put("sharer_name", SecurityUtils.stripHtmlTags(share.getSharerName()));
        result.put("created_at", share.getCreatedAt() != null ? share.getCreatedAt().toString() : null);
        result.put("status", share.getStatus());
        // IronWall v1.47.0: 单文件分享在签发下载凭证前校验文件状态——已删除/封禁立即置失效
        if (Integer.valueOf(1).equals(share.getShareType())) {
            if (share.getFileId() == null) {
                throw new BusinessException(ErrorCode.FILE_NOT_FOUND);
            }
            FileEntity target = fileRepository.findById(share.getFileId())
                    .orElseThrow(() -> new BusinessException(ErrorCode.FILE_NOT_FOUND));
            if (target.getStatus() != 1) {
                share.setStatus(0);
                shareRepository.save(share);
                throw new BusinessException(ErrorCode.SHARE_EXPIRED);
            }
        }
        // IronWall v1.46.0: 下载凭证强制化——HMAC 绑定 share_code|file_id|folder_id|created_at，
        // 24h 过期；分享页每次加载换取新鲜 sig（缺失/错误/过期统一 403）。
        result.put("download_sig", shareLinkSigner.sign(share.getShareCode(),
                share.getFileId(), share.getFolderId(), share.getCreatedAt()));

        if (Integer.valueOf(2).equals(share.getShareType())) {
            if (share.getFolderId() == null) {
                throw new BusinessException(ErrorCode.FOLDER_NOT_FOUND);
            }
            Folder folder = folderRepository.findById(share.getFolderId())
                    .orElseThrow(() -> new BusinessException(ErrorCode.FOLDER_NOT_FOUND));
            result.put("folder_name", SecurityUtils.stripHtmlTags(folder.getName()));
            List<FileEntity> files = fileRepository.findByFolderIdAndStatus(share.getFolderId(), 1);
            List<Map<String, Object>> fileList = new java.util.ArrayList<>();
            for (FileEntity f : files) {
                Map<String, Object> fm = new LinkedHashMap<>();
                fm.put("id", f.getId());
                fm.put("original_name", f.getOriginalName());
                fm.put("file_size", f.getFileSize());
                fm.put("file_type", f.getFileType());
                fm.put("mime_type", f.getMimeType());
                fileList.add(fm);
            }
            result.put("files", fileList);
        } else {
            if (share.getFileId() == null) {
                throw new BusinessException(ErrorCode.FILE_NOT_FOUND);
            }
            FileEntity file = fileRepository.findById(share.getFileId())
                    .orElseThrow(() -> new BusinessException(ErrorCode.FILE_NOT_FOUND));
            result.put("file_name", file.getOriginalName());
            result.put("file_size", file.getFileSize());
        }

        // Include owner's verification badge
        // IronWall v1.6: 旧数据 userId 为空时跳过所有者信息，防止空 ID 查询抛 500
        if (share.getUserId() != null) { userRepository.findById(share.getUserId()).ifPresent(owner -> {
            if (owner.getAvatar() != null) { result.put("owner_avatar", owner.getAvatar()); }
            result.put("owner_username", SecurityUtils.stripHtmlTags(owner.getUsername()));
            result.put("owner_user_code", owner.getUserCode());
            if (owner.getVerificationBadge() != null) {
                result.put("verification_badge", owner.getVerificationBadge());
            }
        }); }

        return result;
    }

    @Transactional
    public FileEntity downloadSharedFile(String code, String pwHash, String pwToken, Long fileId, String sig) {
        code = normalizeShareCode(code);
        Share share = shareRepository.findByShareCode(code)
                .orElseThrow(() -> new BusinessException(ErrorCode.NOT_FOUND));

        // IronWall v1.46.0: 下载凭证强制化——sig 缺失/错误/过期统一 403，
        // 且必须先于状态/密码/限额校验执行（无侧信道）。
        verifyDownloadSig(share, sig);

        // IronWall v1.27.6: 封禁分享给出专属提示（-2 由管理员封禁，区别于过期/失效）
        if (Integer.valueOf(-2).equals(share.getStatus())) {
            throw new BusinessException(ErrorCode.SHARE_BANNED);
        }
        if (!Integer.valueOf(1).equals(share.getStatus())) {
            throw new BusinessException(ErrorCode.SHARE_EXPIRED);
        }

        if (share.getExpireTime() != null && share.getExpireTime().isBefore(LocalDateTime.now())) {
            share.setStatus(0);
            shareRepository.save(share);
            throw new BusinessException(ErrorCode.SHARE_EXPIRED);
        }

        if (share.getPassword() != null && !share.getPassword().isEmpty()) {
            // IronWall v1.22.0: 明文密码路径已移除，仅接受一次性挑战令牌
            boolean passwordOk = pwHash != null && !pwHash.isEmpty() && pwToken != null && !pwToken.isEmpty()
                    && passwordGuardService.verifyChallenge(code, pwToken, pwHash, share.getPassword());
            if (!passwordOk) {
                throw new BusinessException(ErrorCode.SHARE_WRONG_PASSWORD);
            }
        }

        // IronWall v1.3: 全程空安全，防止旧数据 NULL 触发 500
        int count = share.getDownloadCount() == null ? 0 : share.getDownloadCount();
        int limit = share.getDownloadLimit() == null ? -1 : share.getDownloadLimit();
        if (limit > 0 && count >= limit) {
            throw limitReached(share);
        }

        // For folder shares, download individual file by fileId
        if (Integer.valueOf(2).equals(share.getShareType())) {
            if (fileId == null) {
                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(),
                        "文件夹分享需指定具体文件下载，或通过分享页使用打包下载功能");
            }
            FileEntity dlFile = fileRepository.findById(fileId)
                    .orElseThrow(() -> new BusinessException(ErrorCode.FILE_NOT_FOUND));
            if (share.getFolderId() == null) {
                throw new BusinessException(ErrorCode.FOLDER_NOT_FOUND);
            }
            if (!Objects.equals(dlFile.getFolderId(), share.getFolderId())) {
                throw new BusinessException(ErrorCode.FORBIDDEN);
            }
            // IronWall v1.47.0: 文件被删除/封禁/移入回收站后分享不可下载（解封/还原自动恢复）
            if (dlFile.getStatus() != 1) {
                throw new BusinessException(ErrorCode.FILE_NOT_FOUND.getCode(), "文件已被删除或封禁，无法下载");
            }
            if (dlFile.getFilename() == null || dlFile.getFilename().isBlank()) {
                throw new BusinessException(ErrorCode.FILE_NOT_FOUND);
            }
            consumeDownloadQuota(share);
            recordFileDownload(dlFile);
            safeAuditShareDownload(share, dlFile.getOriginalName());
            return dlFile;
        }

        if (share.getFileId() == null) {
            throw new BusinessException(ErrorCode.FILE_NOT_FOUND);
        }
        FileEntity dlFile = fileRepository.findById(share.getFileId())
                .orElseThrow(() -> new BusinessException(ErrorCode.FILE_NOT_FOUND));
        // IronWall v1.47.0: 文件被删除/封禁/移入回收站后分享不可下载（解封/还原自动恢复）
        if (dlFile.getStatus() != 1) {
            throw new BusinessException(ErrorCode.FILE_NOT_FOUND.getCode(), "文件已被删除或封禁，无法下载");
        }
        if (dlFile.getFilename() == null || dlFile.getFilename().isBlank()) {
            throw new BusinessException(ErrorCode.FILE_NOT_FOUND);
        }
        consumeDownloadQuota(share);
        recordFileDownload(dlFile);
        safeAuditShareDownload(share, dlFile.getOriginalName());
        return dlFile;
    }

    /** IronWall v1.47.3: limit-reached error carries quota context for frontend/admin triage. */
    private BusinessException limitReached(Share share) {
        int count = share != null && share.getDownloadCount() != null ? share.getDownloadCount() : 0;
        int limit = share != null && share.getDownloadLimit() != null ? share.getDownloadLimit() : -1;
        return new BusinessException(ErrorCode.SHARE_LIMIT_REACHED.getCode(),
                ErrorCode.SHARE_LIMIT_REACHED.getMessage(), null,
                Map.of("download_count", count, "download_limit", limit, "remaining", 0));
    }
    @Transactional
    // IronWall v1.7: 原子判减一体，杜绝并发下载绕过限次
    private void consumeDownloadQuota(Share share) {
        int updated = shareRepository.incrementDownloadCountIfAllowed(share.getId());
        if (updated > 0) {
            return;
        }
        Share latest = shareRepository.findById(share.getId()).orElse(null);
        if (latest != null) {
            int latestCount = latest.getDownloadCount() == null ? 0 : latest.getDownloadCount();
            int latestLimit = latest.getDownloadLimit() == null ? -1 : latest.getDownloadLimit();
            if (latestLimit > 0 && latestCount >= latestLimit) {
                throw limitReached(latest);
            }
        }
        throw new BusinessException(ErrorCode.SHARE_NOT_FOUND);
    }

    /** IronWall v1.47.4: 分享下载同步计入文件下载次数（管理端文件管理/下载统计的数据源）。 */
    private void recordFileDownload(FileEntity file) {
        if (file != null && file.getId() != null) {
            fileRepository.incrementDownloadCount(file.getId());
        }
    }

    public byte[] downloadSharedFolderAsZip(String code, String pwHash, String pwToken, String sig) throws IOException {
        code = normalizeShareCode(code);
        Share share = shareRepository.findByShareCode(code)
                .orElseThrow(() -> new BusinessException(ErrorCode.NOT_FOUND));

        // IronWall v1.46.0: 打包下载与单文件下载同一凭证策略——sig 强制且先于一切业务校验。
        verifyDownloadSig(share, sig);

        // IronWall v1.27.6: 封禁分享给出专属提示（-2 由管理员封禁，区别于过期/失效）
        if (Integer.valueOf(-2).equals(share.getStatus())) {
            throw new BusinessException(ErrorCode.SHARE_BANNED);
        }
        if (!Integer.valueOf(1).equals(share.getStatus())) {
            throw new BusinessException(ErrorCode.SHARE_EXPIRED);
        }

        if (share.getExpireTime() != null && share.getExpireTime().isBefore(LocalDateTime.now())) {
            share.setStatus(0);
            shareRepository.save(share);
            throw new BusinessException(ErrorCode.SHARE_EXPIRED);
        }

        if (share.getPassword() != null && !share.getPassword().isEmpty()) {
            // IronWall v1.22.0: 明文密码路径已移除，仅接受一次性挑战令牌
            boolean passwordOk = pwHash != null && !pwHash.isEmpty() && pwToken != null && !pwToken.isEmpty()
                    && passwordGuardService.verifyChallenge(code, pwToken, pwHash, share.getPassword());
            if (!passwordOk) {
                throw new BusinessException(ErrorCode.SHARE_WRONG_PASSWORD);
            }
        }

        int count = share.getDownloadCount() == null ? 0 : share.getDownloadCount();
        int limit = share.getDownloadLimit() == null ? -1 : share.getDownloadLimit();
        if (limit > 0 && count >= limit) {
            throw limitReached(share);
        }

        if (!Integer.valueOf(2).equals(share.getShareType())) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "该分享不是文件夹类型");
        }

        if (share.getFolderId() == null) {
            throw new BusinessException(ErrorCode.FOLDER_NOT_FOUND);
        }
        Folder folder = folderRepository.findById(share.getFolderId())
                .orElseThrow(() -> new BusinessException(ErrorCode.FOLDER_NOT_FOUND));

        // IronWall v1.47.9: 类型/目录校验全部通过后才占用下载名额，非法请求不再消耗额度
        consumeDownloadQuota(share);

        String dir = uploadDir == null ? "./uploads" : uploadDir;
        Path basePath = Path.of(dir).toAbsolutePath().normalize();

        // IronWall v1.47.9: 递归收集分享根目录下全部子文件夹与文件（修复嵌套文件漏打包），
        // 条目数与总字节数双上限，条目名净化 + 二次校验防 zip-slip。
        List<ZipCollectEntry> entries = new java.util.ArrayList<>();
        long[] totalBytes = new long[1];
        int[] totalEntries = new int[1];
        collectFolderEntries(share.getFolderId(), "", entries, totalBytes, totalEntries, basePath);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            for (ZipCollectEntry entry : entries) {
                Path filePath = entry.path;
                if (!filePath.startsWith(basePath) || !Files.isRegularFile(filePath)) {
                    continue;
                }
                try {
                    ZipEntry zipEntry = new ZipEntry(entry.zipName);
                    zos.putNextEntry(zipEntry);
                    // IronWall v1.42.0: 加密文件解密后打包
                    try (java.io.InputStream in = storageCrypto.openRead(filePath)) {
                        in.transferTo(zos);
                    }
                    zos.closeEntry();
                    recordFileDownload(entry.file);
                } catch (IOException e) {
                    log.warn("zip entry skipped, fileId={}", entry.file.getId());
                }
            }
        }

        // IronWall v1.47.11: 条目名改为人类可读标注（仅审计文案，无逻辑依赖）
        safeAuditShareDownload(share, folder.getName() + "（文件夹打包）");

        return baos.toByteArray();
    }

    /** IronWall v1.47.9: 打包条目（物理路径 + 分享内相对路径）。 */
    private static final class ZipCollectEntry {
        final FileEntity file;
        final String zipName;
        final Path path;

        ZipCollectEntry(FileEntity file, String zipName, Path path) {
            this.file = file;
            this.zipName = zipName;
            this.path = path;
        }
    }

    /** IronWall v1.47.9: 递归收集文件夹内文件；超限抛 400，危险条目名静默跳过。 */
    private void collectFolderEntries(Long folderId, String relDir, List<ZipCollectEntry> out,
                                      long[] totalBytes, int[] totalEntries, Path basePath) {
        // 配置未注入（单测）或误配为 0/负数时回退默认上限，避免误拦截或空上限放行
        int maxEntries = shareZipMaxEntries > 0 ? shareZipMaxEntries : 1000;
        long maxTotalBytes = shareZipMaxTotalBytes > 0 ? shareZipMaxTotalBytes : 314572800L;
        for (FileEntity file : fileRepository.findByFolderIdAndStatus(folderId, 1)) {
            if (file.getFilename() == null || file.getFilename().isBlank()
                    || file.getOriginalName() == null || file.getOriginalName().isBlank()) {
                continue;
            }
            String segment = sanitizeZipSegment(file.getOriginalName());
            if (segment.isEmpty()) {
                continue;
            }
            String zipName = relDir.isEmpty() ? segment : relDir + "/" + segment;
            if (!isSafeZipEntryName(zipName)) {
                continue;
            }
            long size = file.getFileSize() == null ? 0L : file.getFileSize();
            if (totalBytes[0] + size > maxTotalBytes) {
                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(),
                        "分享内容过大，暂不支持打包下载");
            }
            if (totalEntries[0] >= maxEntries) {
                throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(),
                        "分享文件数量过多，暂不支持打包下载");
            }
            Path filePath = basePath.resolve(file.getFilename()).normalize();
            if (!filePath.startsWith(basePath)) {
                continue;
            }
            out.add(new ZipCollectEntry(file, zipName, filePath));
            totalBytes[0] += size;
            totalEntries[0]++;
        }
        for (Folder child : folderRepository.findByParentIdAndStatus(folderId, 1)) {
            if (child.getName() == null || child.getName().isBlank()) {
                continue;
            }
            String segment = sanitizeZipSegment(child.getName());
            if (segment.isEmpty()) {
                continue;
            }
            String childDir = relDir.isEmpty() ? segment : relDir + "/" + segment;
            if (!isSafeZipEntryName(childDir)) {
                continue;
            }
            collectFolderEntries(child.getId(), childDir, out, totalBytes, totalEntries, basePath);
        }
    }

    /** IronWall v1.47.9: 条目段净化——反斜杠归一、去控制符与首尾斜杠。 */
    private String sanitizeZipSegment(String name) {
        String s = name.replace('\\', '/');
        s = s.replaceAll("[\u0000-\u001f\u007f]", "");
        s = s.replaceAll("^/+", "");
        s = s.replaceAll("/+$", "");
        s = s.replaceAll("/+", "/");
        return s;
    }

    /** IronWall v1.47.9: 条目名安全校验——拒绝绝对路径/盘符/`.`/`..` 段（zip-slip 防线）。 */
    private boolean isSafeZipEntryName(String name) {
        if (name == null || name.isBlank() || name.startsWith("/") || name.contains(":")) {
            return false;
        }
        String[] parts = name.split("/");
        for (String part : parts) {
            if (part.isEmpty() || ".".equals(part) || "..".equals(part)) {
                return false;
            }
        }
        return true;
    }

    /**
     * IronWall v1.46.0: 下载凭证强制校验（单文件绑定 fileId，文件夹绑定 folderId）。
     * 缺失/错误/过期统一 403，与错误 sig 同响应；必须在状态/密码/限额校验之前执行。
     */
    private void verifyDownloadSig(Share share, String sig) {
        if (share == null || share.getShareCode() == null) {
            throw new BusinessException(ErrorCode.SHARE_SIG_INVALID);
        }
        String code = normalizeShareCode(share.getShareCode());
        boolean valid = shareLinkSigner.verify(code,
                Integer.valueOf(1).equals(share.getShareType()) ? share.getFileId() : null,
                Integer.valueOf(2).equals(share.getShareType()) ? share.getFolderId() : null,
                share.getCreatedAt(), sig);
        if (!valid) {
            log.warn("[IronWall] share download rejected: invalid/expired sig code={}", code);
            throw new BusinessException(ErrorCode.SHARE_SIG_INVALID);
        }
    }

    // IronWall v1.11: canonical share codes are lowercase 8-hex; lookups normalize any case,
    // and the repository query compares case-insensitively for legacy lowercase rows
    private String normalizeShareCode(String code) {
        if (code == null) {
            return null;
        }
        return code.trim().toLowerCase(java.util.Locale.ROOT);
    }
}
