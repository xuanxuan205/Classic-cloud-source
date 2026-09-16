package com.jdy.cloud.controller;

import com.jdy.cloud.dto.ApiResponse;
import com.jdy.cloud.service.VersionReleaseService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * IronWall v1.28.7: 版本信息接口（只读）。
 * 用户自助更新开关已整体移除：任何 HTTP 请求都无法触发后端重启，
 * 新版本仅由官方在服务器上手动部署，杜绝“点击更新 -> 重启窗口被攻击者利用”。
 * GET /api/version/info 仅返回当前版本，供官方部署后 curl 验证使用。
 */
@RestController
@RequestMapping("/api/version")
@RequiredArgsConstructor
public class VersionController {

    private final VersionReleaseService versionReleaseService;

    @GetMapping("/info")
    public ResponseEntity<ApiResponse<Map<String, Object>>> info() {
        return ResponseEntity.ok(ApiResponse.ok(versionReleaseService.info()));
    }
}
