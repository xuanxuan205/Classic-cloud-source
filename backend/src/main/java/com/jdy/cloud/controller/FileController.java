package com.jdy.cloud.controller;

import com.jdy.cloud.dto.ApiResponse;
import com.jdy.cloud.dto.FileUploadResult;
import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.ErrorCode;
import com.jdy.cloud.model.FileEntity;
import com.jdy.cloud.model.Folder;
import com.jdy.cloud.repository.FileRepository;
import com.jdy.cloud.repository.SystemConfigRepository;
import com.jdy.cloud.security.StorageCryptoService;
import com.jdy.cloud.security.ApiCryptoFilter;
import com.jdy.cloud.security.UserPrincipal;
import com.jdy.cloud.service.FileService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpHeaders;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@RestController
@RequestMapping("/api/files")
@RequiredArgsConstructor
public class FileController {

    private final FileService fileService;
    private final FileRepository fileRepository;
    private final SystemConfigRepository systemConfigRepository;
    private final StorageCryptoService storageCrypto;

    @Value("${app.storage.upload-dir:${UPLOAD_DIR:./uploads}}")
    private String uploadDir;

    @PostMapping("/upload")
    public ResponseEntity<ApiResponse<FileUploadResult>> upload(
            @AuthenticationPrincipal UserPrincipal principal,
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "folderId", required = false) Long folderId,
            @RequestHeader(value = ApiCryptoFilter.FILE_HASH_HEADER) String fileHash) throws Exception {
        log.info("UPLOAD userId={} name={} size={}", principal.getUserId(), file.getOriginalFilename(), file.getSize());
        FileUploadResult result = fileService.uploadFile(principal.getUserId(), file, folderId, fileHash);
        log.info("UPLOAD done id={}", result.getId());
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    // ================= IronWall v1.28.0: 秒传 + 分片续传 =================

    @PostMapping("/upload/check")
    public ResponseEntity<ApiResponse<Map<String, Object>>> checkUpload(
            @AuthenticationPrincipal UserPrincipal principal,
            @RequestBody Map<String, Object> body) {
        String filename = str(body.get("filename"));
        Long size = lng(body.get("size"));
        String hash = str(body.get("hash"));
        Map<String, Object> result = fileService.checkUpload(principal.getUserId(), filename, size, hash);
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    @PostMapping("/upload/chunk")
    public ResponseEntity<ApiResponse<Map<String, Object>>> uploadChunk(
            @AuthenticationPrincipal UserPrincipal principal,
            @RequestParam("file") MultipartFile file,
            @RequestParam("hash") String hash,
            @RequestParam("index") int index,
            @RequestParam("total") int total,
            @RequestHeader(value = ApiCryptoFilter.CHUNK_HASH_HEADER) String chunkHash) throws Exception {
        int saved = fileService.saveChunk(principal.getUserId(), hash, index, total, file, chunkHash);
        return ResponseEntity.ok(ApiResponse.ok(Map.of("index", saved)));
    }

    @PostMapping("/upload/merge")
    public ResponseEntity<ApiResponse<FileUploadResult>> mergeChunks(
            @AuthenticationPrincipal UserPrincipal principal,
            @RequestBody Map<String, Object> body) {
        String filename = str(body.get("filename"));
        Long size = lng(body.get("size"));
        String hash = str(body.get("hash"));
        int total = body.get("total") == null ? 0 : Integer.parseInt(String.valueOf(body.get("total")));
        // IronWall v1.28.9: 同时兼容 snake_case 与 camelCase，避免 folderId 被忽略导致文件恒落根目录
        Long folderId = body.containsKey("folder_id") ? lng(body.get("folder_id"))
                : (body.containsKey("folderId") ? lng(body.get("folderId")) : null);
        String mimeType = body.containsKey("mime_type") ? str(body.get("mime_type"))
                : (body.containsKey("mimeType") ? str(body.get("mimeType")) : str(body.get("mime")));
        FileUploadResult result = fileService.mergeChunks(principal.getUserId(), hash, filename, size, total, folderId, mimeType);
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    private String str(Object v) {
        return v == null ? null : String.valueOf(v);
    }

    private Long lng(Object v) {
        if (v == null || String.valueOf(v).isBlank()) return null;
        try {
            return Long.parseLong(String.valueOf(v));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    @GetMapping("/list")
    public ResponseEntity<ApiResponse<Map<String, Object>>> list(
            @AuthenticationPrincipal UserPrincipal principal,
            @RequestParam(value = "folderId", required = false) Long folderId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Long userId = principal.getUserId();
        log.info("LIST userId={} folderId={}", userId, folderId);
        Page<FileEntity> pageResult = fileService.listFiles(userId, folderId, page, size);
        log.info("LIST totalElements={} contentSize={}", pageResult.getTotalElements(), pageResult.getContent().size());
        List<Map<String, Object>> content = new ArrayList<>();
        for (FileEntity f : pageResult.getContent()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("id", f.getId());
            item.put("filename", f.getFilename());
            item.put("original_name", f.getOriginalName());
            item.put("file_size", f.getFileSize());
            item.put("file_type", f.getFileType());
            item.put("mime_type", f.getMimeType());
            item.put("file_hash", f.getFileHash() != null ? f.getFileHash() : "");
            item.put("folder_id", f.getFolderId());
            item.put("is_shared", f.getIsShared());
            item.put("download_count", f.getDownloadCount());
            item.put("created_at", f.getCreatedAt() != null ? f.getCreatedAt().toString() : "");
            item.put("status", f.getStatus());
            content.add(item);
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("content", content);
        result.put("totalElements", pageResult.getTotalElements());
        result.put("totalPages", pageResult.getTotalPages());
        result.put("number", pageResult.getNumber());
        result.put("size", pageResult.getSize());
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    @GetMapping("/storage")
    public ResponseEntity<ApiResponse<Map<String, Object>>> storage(
            @AuthenticationPrincipal UserPrincipal principal) {
        return ResponseEntity.ok(ApiResponse.ok(fileService.getStorageStats(principal.getUserId())));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> delete(@AuthenticationPrincipal UserPrincipal principal,
                                                     @PathVariable Long id) {
        fileService.deleteFile(principal.getUserId(), id);
        return ResponseEntity.ok(ApiResponse.ok(null));
    }

    @GetMapping("/download/{id}")
    public ResponseEntity<Resource> download(@AuthenticationPrincipal UserPrincipal principal,
                                              @PathVariable Long id) {
        FileEntity file = fileService.getFileForDownload(principal.getUserId(), id);
        Path uploadPath = Path.of(uploadDir).toAbsolutePath().normalize();
        Path filePath = uploadPath.resolve(file.getFilename()).normalize();
        if (!filePath.startsWith(uploadPath) || !java.nio.file.Files.exists(filePath)) {
            throw new BusinessException(ErrorCode.FILE_NOT_FOUND);
        }
        // IronWall v1.42.0: 加密文件流式解密下载（明文文件保持原资源类型）
        Resource resource = storageCrypto.resourceOf(filePath);
        String encodedName = URLEncoder.encode(file.getOriginalName(), StandardCharsets.UTF_8)
                .replace("+", "%20");
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + encodedName + "\"")
                .body(resource);
    }

    @PostMapping("/folder")
    public ResponseEntity<ApiResponse<Map<String, Object>>> createFolder(
            @AuthenticationPrincipal UserPrincipal principal,
            @RequestParam String name,
            @RequestParam(required = false) Long parentId) {
        Folder folder = fileService.createFolder(principal.getUserId(), name, parentId);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", folder.getId());
        result.put("name", folder.getName());
        result.put("parent_id", folder.getParentId());
        result.put("created_at", folder.getCreatedAt() != null ? folder.getCreatedAt().toString() : "");
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    @GetMapping("/folder/list")
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> listFolders(
            @AuthenticationPrincipal UserPrincipal principal,
            @RequestParam(required = false) Long parentId) {
        List<Folder> folders = fileService.listFolders(principal.getUserId(), parentId);
        List<Map<String, Object>> result = folders.stream().map(f -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", f.getId());
            m.put("name", f.getName());
            m.put("parent_id", f.getParentId());
            m.put("created_at", f.getCreatedAt() != null ? f.getCreatedAt().toString() : "");
            return m;
        }).collect(Collectors.toList());
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    @DeleteMapping("/folder/{id}")
    public ResponseEntity<ApiResponse<Void>> deleteFolder(@AuthenticationPrincipal UserPrincipal principal,
                                                           @PathVariable Long id) {
        fileService.deleteFolder(principal.getUserId(), id);
        return ResponseEntity.ok(ApiResponse.ok(null));
    }

    @GetMapping("/recycle")
    public ResponseEntity<ApiResponse<Map<String, Object>>> recycleBin(
            @AuthenticationPrincipal UserPrincipal principal,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        log.info("RECYCLE userId={} page={} size={}", principal.getUserId(), page, size);
        Page<FileEntity> pageResult = fileService.getDeletedFiles(principal.getUserId(), page, size);
        log.info("RECYCLE totalElements={}", pageResult.getTotalElements());
        List<Map<String, Object>> content = new ArrayList<>();
        for (FileEntity f : pageResult.getContent()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("id", f.getId());
            item.put("filename", f.getFilename());
            item.put("original_name", f.getOriginalName());
            item.put("file_size", f.getFileSize());
            item.put("file_type", f.getFileType());
            item.put("created_at", f.getCreatedAt() != null ? f.getCreatedAt().toString() : "");
            content.add(item);
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("content", content);
        result.put("totalElements", pageResult.getTotalElements());
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    @PostMapping("/{id}/restore")
    public ResponseEntity<ApiResponse<Void>> restoreFile(@AuthenticationPrincipal UserPrincipal principal,
                                                          @PathVariable Long id) {
        fileService.restoreFile(principal.getUserId(), id);
        return ResponseEntity.ok(ApiResponse.ok("恢复成功", null));
    }

    @DeleteMapping("/{id}/permanent")
    public ResponseEntity<ApiResponse<Void>> permanentDelete(@AuthenticationPrincipal UserPrincipal principal,
                                                              @PathVariable Long id) {
        fileService.permanentDeleteFile(principal.getUserId(), id);
        return ResponseEntity.ok(ApiResponse.ok("永久删除成功", null));
    }

    @GetMapping("/avatar/{filename}")
    public ResponseEntity<Resource> getAvatar(@PathVariable String filename) {
        // IronWall v1.9: 与上传共用同一候选目录列表（先主后备），旧数据/兜底数据都能读到
        Path filePath = null;
        for (Path basePath : com.jdy.cloud.util.StoragePaths.avatarDirs(uploadDir)) {
            Path candidate = basePath.resolve(filename).normalize();
            if (candidate.startsWith(basePath) && java.nio.file.Files.exists(candidate)) {
                filePath = candidate;
                break;
            }
        }
        if (filePath == null) {
            throw new BusinessException(ErrorCode.NOT_FOUND);
        }
        Resource resource = new FileSystemResource(filePath);
        String contentType = "image/png";
        if (filename.endsWith(".jpg") || filename.endsWith(".jpeg")) {
            contentType = "image/jpeg";
        } else if (filename.endsWith(".gif")) {
            contentType = "image/gif";
        } else if (filename.endsWith(".webp")) {
            contentType = "image/webp";
        }
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .cacheControl(CacheControl.maxAge(java.time.Duration.ofHours(1)))
                .body(resource);
    }

    @GetMapping("/ping")
    public ResponseEntity<Map<String, String>> ping() {
        // IronWall v1.20: 去除 Java 版本/内部版本号/站点名等指纹，只返回无信息量的 pong
        Map<String, String> map = new LinkedHashMap<>();
        map.put("status", "pong");
        return ResponseEntity.ok(map);
    }
}
