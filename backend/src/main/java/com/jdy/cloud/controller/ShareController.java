package com.jdy.cloud.controller;

import com.jdy.cloud.dto.ApiResponse;
import com.jdy.cloud.dto.CreateShareRequest;
import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.ErrorCode;
import com.jdy.cloud.model.FileEntity;
import com.jdy.cloud.model.Folder;
import com.jdy.cloud.model.Share;
import com.jdy.cloud.security.UserPrincipal;
import com.jdy.cloud.security.ShareLinkSigner;
import com.jdy.cloud.security.SharePasswordLimiter;
import com.jdy.cloud.security.ShareLookupLimiter;
import com.jdy.cloud.security.ShareDownloadLimiter;
import com.jdy.cloud.security.StorageCryptoService;
import com.jdy.cloud.util.ClientIpUtils;
import com.jdy.cloud.service.PasswordGuardService;
import com.jdy.cloud.service.ShareService;
import com.jdy.cloud.repository.ShareRepository;
import com.jdy.cloud.repository.FileRepository;
import com.jdy.cloud.repository.FolderRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletRequest;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

@Slf4j
@RestController
@RequestMapping("/api/shares")
@RequiredArgsConstructor
public class ShareController {

    private final ShareService shareService;
    private final ShareRepository shareRepository;
    private final FileRepository fileRepository;
    private final FolderRepository folderRepository;
    private final PasswordGuardService passwordGuardService;
    private final SharePasswordLimiter sharePasswordLimiter;
    private final ShareLookupLimiter shareLookupLimiter;
    private final ShareDownloadLimiter shareDownloadLimiter;
    private final ShareLinkSigner shareLinkSigner;
    private final StorageCryptoService storageCrypto;

    @Value("${app.storage.upload-dir:${UPLOAD_DIR:./uploads}}")
    private String uploadDir;

    @GetMapping("/list")
    public ResponseEntity<ApiResponse<Map<String, Object>>> list(            @AuthenticationPrincipal UserPrincipal principal,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        // IronWall v1.12: 匿名访问不再因 principal 为空落入 500，统一 401
        if (principal == null) {
            throw new BusinessException(ErrorCode.UNAUTHORIZED);
        }
        if (page < 0 || size < 1 || size > 100) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "分页参数无效");
        }
        // IronWall v1.25.0: 兼容 1-based 页码（page=1 即第一页），page=0 仍为第一页
        int normalizedPage = page > 0 ? page - 1 : page;
        Page<Share> shares = shareService.listShares(principal.getUserId(), normalizedPage, size);
        List<Map<String, Object>> content = new ArrayList<>();
        for (Share s : shares.getContent()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("id", s.getId());
            item.put("share_type", s.getShareType());
            item.put("file_id", s.getFileId());
            item.put("folder_id", s.getFolderId());
            item.put("share_code", s.getShareCode());
            item.put("download_limit", s.getDownloadLimit());
            item.put("download_count", s.getDownloadCount());
            item.put("expire_time", s.getExpireTime() != null ? s.getExpireTime().toString() : null);
            item.put("status", s.getStatus());
            item.put("has_password", s.getPassword() != null && !s.getPassword().isEmpty());
            // Lookup file/folder name
            if (s.getFileId() != null) {
                fileRepository.findById(s.getFileId()).ifPresent(f -> {
                    item.put("file_name", f.getOriginalName());
                    item.put("file_size", f.getFileSize());
                });
            } else if (s.getFolderId() != null) {
                folderRepository.findById(s.getFolderId()).ifPresent(f -> {
                    item.put("file_name", f.getName());
                    item.put("file_size", 0L);
                });
            }
            item.put("description", s.getDescription());
            item.put("created_at", s.getCreatedAt() != null ? s.getCreatedAt().toString() : "");
            content.add(item);
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("content", content);
        result.put("totalElements", shares.getTotalElements());
        result.put("totalPages", shares.getTotalPages());
        result.put("number", shares.getNumber());
        result.put("size", shares.getSize());
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    @PostMapping("/create")
    public ResponseEntity<ApiResponse<Map<String, Object>>> create(@AuthenticationPrincipal UserPrincipal principal,
                                                      @Valid @RequestBody CreateShareRequest request) {
        Share share = shareService.createShare(principal.getUserId(), request);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", share.getId());
        result.put("share_code", share.getShareCode());
        result.put("share_type", share.getShareType());
        result.put("file_id", share.getFileId());
        result.put("folder_id", share.getFolderId());
        result.put("download_limit", share.getDownloadLimit());
        result.put("expire_time", share.getExpireTime() != null ? share.getExpireTime().toString() : null);
        result.put("created_at", share.getCreatedAt() != null ? share.getCreatedAt().toString() : "");
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> delete(@AuthenticationPrincipal UserPrincipal principal,
                                                     @PathVariable Long id) {
        shareService.deleteShare(principal.getUserId(), id);
        return ResponseEntity.ok(ApiResponse.ok("deleted", null));
    }

    /**
     * 密码护航安全引擎 - 获取挑战令牌
     * 前端调用此接口获取一次性令牌，用 SHA256(token+password) 代替明文
     */
    @GetMapping("/challenge/{code}")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getChallenge(@PathVariable String code,
                                                                          HttpServletRequest request) {
        code = code == null ? code : code.trim().toLowerCase(java.util.Locale.ROOT);
        shareLookupLimiter.checkAllowed(ClientIpUtils.getClientIp(request));
        // 先验证分享存在
        shareRepository.findByShareCode(code)
                .orElseThrow(() -> new com.jdy.cloud.exception.BusinessException(
                    com.jdy.cloud.exception.ErrorCode.SHARE_NOT_FOUND));
        
        PasswordGuardService.ChallengeResponse challenge = passwordGuardService.generateChallenge(code);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("token", challenge.token);
        result.put("expiresAt", challenge.expiresAt);
        result.put("ttlSeconds", challenge.ttlSeconds);
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    // IronWall v1.7: 空分享码 / 根路径统一 404，不再落入模板匹配产生 500
    @GetMapping({"", "/"})
    public ResponseEntity<ApiResponse<Void>> shareRoot() {
        return ResponseEntity.status(404).body(ApiResponse.error(404, "分享不存在"));
    }

    @GetMapping("/{code}")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getShareInfo(
            @PathVariable String code,
            @RequestParam(required = false) String pw_hash,
            @RequestParam(required = false) String pw_token,
            HttpServletRequest request) {
        String clientIp = ClientIpUtils.getClientIp(request);
        code = code == null ? code : code.trim().toLowerCase(java.util.Locale.ROOT);
        shareLookupLimiter.checkAllowed(clientIp);
        sharePasswordLimiter.checkAllowed(code, clientIp);
        shareDownloadLimiter.checkAllowed(code, clientIp, false, currentUserIdOrNull());
        try {
            Map<String, Object> info = shareService.getShareInfo(code, pw_hash, pw_token);
            sharePasswordLimiter.clear(code, clientIp);
            return ResponseEntity.ok(ApiResponse.ok(info));
        } catch (BusinessException e) {
            if (e.getCode() == ErrorCode.SHARE_WRONG_PASSWORD.getCode()) {
                sharePasswordLimiter.recordFailure(code, clientIp);
            }
            throw e;
        }
    }

    @GetMapping({"/download", "/download/"})
    public ResponseEntity<ApiResponse<Void>> downloadNoCode() {
        return ResponseEntity.status(404).body(ApiResponse.error(404, "分享码不能为空"));
    }

    @GetMapping("/download/{code}")
    public ResponseEntity<?> download(@PathVariable String code,
                                       @RequestParam(required = false) String pw_hash,
                                       @RequestParam(required = false) String pw_token,
                                       @RequestParam(required = false) Long fileId,
                                       @RequestParam(required = false) String sig,
                                       HttpServletRequest request) {
        String clientIp = ClientIpUtils.getClientIp(request);
        code = code == null ? code : code.trim().toLowerCase(java.util.Locale.ROOT);
        shareLookupLimiter.checkAllowed(clientIp);
        sharePasswordLimiter.checkAllowed(code, clientIp);
        // IronWall v1.46.0: download_sig 强制化——缺失/错误/过期统一由服务端 403；
        // 缺失 sig 按收紧额度限流（防匿名批量抓取），验证本身绝不“可选”。
        boolean signed = sig != null && !sig.isBlank();
        shareDownloadLimiter.checkAllowed(code, clientIp, signed, currentUserIdOrNull());
        try {
            FileEntity file = shareService.downloadSharedFile(code, pw_hash, pw_token, fileId, sig);
            sharePasswordLimiter.clear(code, clientIp);
            if (file.getFilename() == null || file.getFilename().isBlank()) {
                return ResponseEntity.status(404)
                        .body(ApiResponse.error(404, "文件不存在或已被删除"));
            }
            Path basePath = Path.of(uploadDir).toAbsolutePath().normalize();
            Path filePath = basePath.resolve(file.getFilename()).normalize();
            if (!filePath.startsWith(basePath)) {
                return ResponseEntity.badRequest()
                        .body(ApiResponse.error(400, "非法的文件路径"));
            }
            if (!Files.exists(filePath) || !Files.isReadable(filePath)) {
                return ResponseEntity.status(404)
                        .body(ApiResponse.error(404, "文件不存在或已被删除"));
            }
            // IronWall v1.42.0: 加密文件流式解密下载
            Resource resource = storageCrypto.resourceOf(filePath);
            String encodedName = URLEncoder.encode(
                    file.getOriginalName() != null ? file.getOriginalName() : "download",
                    StandardCharsets.UTF_8);
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .header(HttpHeaders.ACCEPT_RANGES, "none")
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            "attachment; filename=\"" + encodedName + "\"")
                    .body(resource);
        } catch (BusinessException e) {
            if (e.getCode() == ErrorCode.SHARE_WRONG_PASSWORD.getCode()) {
                sharePasswordLimiter.recordFailure(code, clientIp);
            }
            throw e;
        } catch (Exception e) {
            log.error("Download failed for code: {}", code, e);
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error(ErrorCode.INTERNAL_ERROR.getCode(), ErrorCode.INTERNAL_ERROR.getMessage()));
        }
    }

    @GetMapping({"/download-zip", "/download-zip/"})
    public ResponseEntity<ApiResponse<Void>> downloadZipNoCode() {
        return ResponseEntity.status(404).body(ApiResponse.error(404, "分享码不能为空"));
    }

    @GetMapping("/download-zip/{code}")
    public ResponseEntity<?> downloadZip(@PathVariable String code,
                                         @RequestParam(required = false) String pw_hash,
                                         @RequestParam(required = false) String pw_token,
                                         @RequestParam(required = false) String sig,
                                         HttpServletRequest request) {
        String clientIp = ClientIpUtils.getClientIp(request);
        code = code == null ? code : code.trim().toLowerCase(java.util.Locale.ROOT);
        shareLookupLimiter.checkAllowed(clientIp);
        sharePasswordLimiter.checkAllowed(code, clientIp);
        // IronWall v1.46.0: 打包下载与单文件下载同一凭证策略——sig 强制，服务端权威校验。
        boolean signed = sig != null && !sig.isBlank();
        shareDownloadLimiter.checkAllowed(code, clientIp, signed, currentUserIdOrNull());
        try {
            byte[] zipBytes = shareService.downloadSharedFolderAsZip(code, pw_hash, pw_token, sig);
            sharePasswordLimiter.clear(code, clientIp);
            ByteArrayResource resource = new ByteArrayResource(zipBytes);
            Share shareInfo = shareRepository.findByShareCode(code).orElse(null);
            String filename = "download.zip";
            if (shareInfo != null && shareInfo.getFolderId() != null) {
                Folder folder = folderRepository.findById(shareInfo.getFolderId()).orElse(null);
                if (folder != null) {
                    filename = folder.getName() + ".zip";
                }
            }
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .header(HttpHeaders.ACCEPT_RANGES, "none")
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            "attachment; filename=\"" + URLEncoder.encode(filename, StandardCharsets.UTF_8) + "\"")
                    .body(resource);
        } catch (BusinessException e) {
            if (e.getCode() == ErrorCode.SHARE_WRONG_PASSWORD.getCode()) {
                sharePasswordLimiter.recordFailure(code, clientIp);
            }
            throw e;
        } catch (Exception e) {
            log.error("Zip download failed for code: {}", code, e);
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.error(ErrorCode.INTERNAL_ERROR.getCode(), ErrorCode.INTERNAL_ERROR.getMessage()));
        }
    }

    /**
     * IronWall v1.47.3: joint-dimension rate-limit key for public download endpoints.
     * Authenticated users are bucketed by account id (same NAT exit IP does not share quota);
     * anonymous / missing security context falls back to null (IP-based bucket).
     */
    private Long currentUserIdOrNull() {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.isAuthenticated()
                    && auth.getPrincipal() instanceof UserPrincipal principal) {
                return principal.getUserId();
            }
        } catch (Exception ignored) {
            // any security-context read failure on public endpoints is treated as anonymous
        }
        return null;
    }
}
