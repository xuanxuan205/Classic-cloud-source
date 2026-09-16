package com.jdy.cloud.controller;

import com.jdy.cloud.dto.ApiResponse;
import com.jdy.cloud.model.SystemConfig;
import com.jdy.cloud.repository.SystemConfigRepository;
import com.jdy.cloud.security.UploadPolicy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * IronWall v1.27.11: 公开站点信息接口。
 * 首页读取站点名、站点描述与站点维护公告（disabled_notice）并展示。
 * 维护公告仅由管理员写入，前台只读。
 */
@Slf4j
@RestController
@RequestMapping("/api/site")
@RequiredArgsConstructor
public class SiteController {

    private final SystemConfigRepository systemConfigRepository;

    @GetMapping("/info")
    public ResponseEntity<ApiResponse<Map<String, String>>> info() {
        Map<String, String> info = new LinkedHashMap<>();
        info.put("site_name", value("site_name", "经典云网盘"));
        info.put("site_description", value("site_description", ""));
        info.put("disabled_notice", value("disabled_notice", ""));
        // IronWall v1.46.0: 上传阈值下发——前端按服务端配置分流，消除前后端阈值不一致。
        info.put("upload_direct_max_bytes", String.valueOf(UploadPolicy.DIRECT_UPLOAD_MAX_BYTES));
        info.put("upload_chunk_size_bytes", String.valueOf(UploadPolicy.CHUNK_SIZE_BYTES));
        info.put("upload_max_file_bytes", String.valueOf(UploadPolicy.MAX_FILE_BYTES));
        info.put("upload_admin_max_file_bytes", String.valueOf(UploadPolicy.ADMIN_MAX_FILE_BYTES));
        info.put("upload_policy_version", UploadPolicy.POLICY_VERSION);
        info.put("upload_ext_whitelist", String.join(",", UploadPolicy.NORMAL_USER_ALLOWED_EXTENSIONS.stream().sorted().toList()));
        return ResponseEntity.ok(ApiResponse.ok(info));
    }

    private String value(String key, String fallback) {
        try {
            return systemConfigRepository.findByConfigKey(key)
                    .map(SystemConfig::getConfigValue)
                    .orElse(fallback);
        } catch (Exception e) {
            log.warn("[IronWall] read site config {} failed: {}", key, e.getMessage());
            return fallback;
        }
    }
}
