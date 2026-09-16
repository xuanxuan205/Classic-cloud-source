package com.jdy.cloud.controller;

import com.jdy.cloud.dto.AnnouncementRequest;
import com.jdy.cloud.dto.ApiResponse;
import com.jdy.cloud.dto.UpdateUserRequest;
import com.jdy.cloud.model.Announcement;
import com.jdy.cloud.model.FileEntity;
import com.jdy.cloud.model.AuditLog;
import com.jdy.cloud.model.AttackLog;
import com.jdy.cloud.model.SystemConfig;
import com.jdy.cloud.repository.AttackLogRepository;
import com.jdy.cloud.repository.SystemConfigRepository;
import com.jdy.cloud.repository.UserRepository;
import com.jdy.cloud.model.Share;
import com.jdy.cloud.model.User;
import com.jdy.cloud.security.UserPrincipal;
import com.jdy.cloud.security.AttackGuardService;
import com.jdy.cloud.security.DecoyPortTrapService;
import com.jdy.cloud.security.DdosDefenseService;
import com.jdy.cloud.security.HoneypotLayerService;
import com.jdy.cloud.security.AlertNotifierService;
import com.jdy.cloud.security.ServerShieldService;
import com.jdy.cloud.security.ShareDownloadLimiter;
import com.jdy.cloud.security.SignFailureAuditService;
import com.jdy.cloud.security.TrafficAggregationService;
import com.jdy.cloud.security.TrapService;
import com.jdy.cloud.security.UserRateLimitFilter;
import com.jdy.cloud.security.AccountDeviceTracker;
import com.jdy.cloud.service.AdminService;
import com.jdy.cloud.service.AppealCenterService;
import com.jdy.cloud.service.AuditLogService;
import com.jdy.cloud.service.ThreatIntelService;
import com.jdy.cloud.service.VerificationCodeService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@Slf4j
@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final AdminService adminService;
    private final AppealCenterService appealCenterService;
    private final SystemConfigRepository systemConfigRepository;
    private final AuditLogService auditLogService;
    private final UserRepository userRepository;
    private final VerificationCodeService verificationCodeService;
    private final AttackLogRepository attackLogRepository;
    private final AttackGuardService attackGuardService;
    private final ThreatIntelService threatIntelService;
    private final HoneypotLayerService honeypotLayerService;
    private final TrapService trapService;
    private final ServerShieldService serverShieldService;
    private final DecoyPortTrapService decoyPortTrapService;
    private final DdosDefenseService ddosDefenseService;
    private final AlertNotifierService alertNotifierService;
    private final TrafficAggregationService trafficAggregationService;
    private final SignFailureAuditService signFailureAuditService;
    private final UserRateLimitFilter userRateLimitFilter;
    private final AccountDeviceTracker accountDeviceTracker;
    private final ShareDownloadLimiter shareDownloadLimiter;


    private String resolveTargetUsername(Long userId) {
        if (userId == null) return "unknown";
        return userRepository.findById(userId).map(u -> u.getUsername()).orElse("user-" + userId);
    }

    @GetMapping("/dashboard")
    public ResponseEntity<ApiResponse<Map<String, Object>>> dashboard() {
        return ResponseEntity.ok(ApiResponse.ok(adminService.getDashboardStats()));
    }

    @GetMapping("/security/summary")
    public ResponseEntity<ApiResponse<Map<String, Object>>> securitySummary() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("engine", AttackGuardService.ENGINE_FULL_NAME);
        result.put("enabled", attackGuardService.isEnabled());
        List<Map<String, Object>> blocked = new ArrayList<>();
        java.util.List<String> geoWarmupIps = new ArrayList<>();
        for (AttackGuardService.BlockInfo b : attackGuardService.getBlockedIps()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("ip", b.ip);
            // IronWall v1.28.5: IP 自动定位（列表先用缓存，后台预热自动补全）
            item.put("geo", threatIntelService.geoFromCache(b.ip));
            if (item.get("geo") == null) geoWarmupIps.add(b.ip);
            item.put("score", b.score);
            item.put("block_count", b.blockCount);
            item.put("blocked_until", java.time.LocalDateTime.ofInstant(
                    java.time.Instant.ofEpochMilli(b.blockedUntil), java.time.ZoneId.systemDefault()).toString());
            item.put("blocked_seconds", b.blockedSeconds);
            blocked.add(item);
        }
        result.put("blocked_ips", blocked);
        result.put("blocked_count", blocked.size());
        threatIntelService.warmUpGeoAsync(geoWarmupIps);
        long total = 0;
        long today = 0;
        try { total = attackLogRepository.count(); } catch (Exception ignored) { }
        try { today = attackLogRepository.countByCreatedAtAfter(java.time.LocalDate.now().atStartOfDay()); } catch (Exception ignored) { }
        result.put("total_attacks", total);
        result.put("today_attacks", today);
        // IronWall v1.17: 主动防御与威慑引擎状态
        Map<String, Object> defense = new LinkedHashMap<>();
        defense.put("enabled", true);
        defense.put("version", AttackGuardService.ENGINE_VERSION);
        long honeypotHits = 0;
        try { honeypotHits = attackLogRepository.countByAttackType(AttackGuardService.TYPE_HONEYPOT); } catch (Exception ignored) { }
        defense.put("honeypot_hits", honeypotHits);
        long tarpitActive = 0;
        for (Map<String, Object> a : attackGuardService.getAttackerSummaries()) {
            if (Boolean.TRUE.equals(a.get("tarpit"))) tarpitActive++;
        }
        defense.put("tarpit_active", tarpitActive);
        List<Map<String, Object>> segments = new ArrayList<>();
        for (AttackGuardService.SegmentInfo s : attackGuardService.getBlockedSegments()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("segment", s.segment);
            item.put("block_count", s.blockCount);
            item.put("blocked_until", java.time.LocalDateTime.ofInstant(
                    java.time.Instant.ofEpochMilli(s.blockedUntil), java.time.ZoneId.systemDefault()).toString());
            item.put("blocked_seconds", s.blockedSeconds);
            segments.add(item);
        }
        defense.put("blocked_segments", segments);
        defense.put("segment_count", segments.size());
        // IronWall v1.18: 五层蜜罐分层触网计数（L1~L5）
        Map<Integer, Long> layerTouches = honeypotLayerService.layerCounts();
        Map<String, Object> honeypotLayers = new LinkedHashMap<>();
        for (int layer = 1; layer <= 7; layer++) {
            honeypotLayers.put("L" + layer, layerTouches.getOrDefault(layer, 0L));
        }
        defense.put("honeypot_layers", honeypotLayers);
        defense.put("threat_intel_enabled", threatIntelService.isEnabled());
        // IronWall v1.44.0: 移动/家宽运营商出口熔断面板数据
        defense.put("mobile_fuse", attackGuardService.mobileFuseStats());
        // IronWall v1.26.0: 五层假端口陷阱清单
        defense.put("decoy_ports", decoyPortTrapService.snapshot());
        // IronWall v1.35.0: DDoS 分层防御摘要
        defense.put("ddos", ddosDefenseService.summary());
        // IronWall v1.38.0: 告警联动 + 跨IP聚合观测快照（铁壁控制台弹窗数据源）
        defense.put("alerts", alertNotifierService.snapshot());
        defense.put("aggregation", trafficAggregationService.snapshot());
        result.put("defense_engine", defense);
        // IronWall v1.41.0: 签名失败审计（仅统计，不计分不封禁）
        result.put("sign_audit", signFailureAuditService.stats());
        // IronWall v1.44.0: 用户级限速面板统计
        result.put("user_rate_limit", userRateLimitFilter.stats());
        // IronWall v1.45.0: 账号级设备指纹观察快照（只统计不拦截）
        result.put("account_profiles", accountDeviceTracker.snapshot());
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    /** IronWall v1.38.0: 最近告警列表（铁壁控制台弹窗/滚动告警）。 */
    @GetMapping("/security/alerts")
    public ResponseEntity<ApiResponse<Map<String, Object>>> securityAlerts() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("alerts", alertNotifierService.recent(50));
        result.put("total", alertNotifierService.snapshot().get("total"));
        result.put("aggregation", trafficAggregationService.snapshot());
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    /** IronWall v1.35.0: DDoS 溯源取证报告（Top 来源/僵尸网络集群/攻击源交叉/事件尾部）。 */
    @GetMapping("/security/ddos-forensics")
    public ResponseEntity<ApiResponse<Map<String, Object>>> ddosForensics() {
        return ResponseEntity.ok(ApiResponse.ok(ddosDefenseService.forensicReport()));
    }

    /** IronWall v1.35.0: 单 IP DDoS 溯源（速率/geo/代理判定/滥用报告）。 */
    @GetMapping("/security/ddos-forensics/{ip}")
    public ResponseEntity<ApiResponse<Map<String, Object>>> ddosForensicsForIp(@PathVariable String ip) {
        return ResponseEntity.ok(ApiResponse.ok(ddosDefenseService.forensicForIp(ip)));
    }

    @GetMapping("/security/attackers")
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> attackers() {
        return ResponseEntity.ok(ApiResponse.ok(attackGuardService.getAttackerSummaries()));
    }

    /** IronWall v1.25.1: 服务器前置护盾状态（fail2ban / 防火墙 / SSH / MySQL / 五层摘要）。 */
    @GetMapping("/security/server-shield")
    public ResponseEntity<ApiResponse<Map<String, Object>>> serverShield(@RequestParam(required = false, defaultValue = "false") boolean refresh) {
        return ResponseEntity.ok(ApiResponse.ok(serverShieldService.getShieldStatus(refresh)));
    }

    /** IronWall v1.26.0: 五层假端口陷阱清单（管理面板展示）。 */
    @GetMapping("/security/decoy-ports")
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> decoyPorts() {
        return ResponseEntity.ok(ApiResponse.ok(decoyPortTrapService.snapshot()));
    }

    /** IronWall v1.26.0: 管理员手动轮换假端口陷阱。 */
    @PostMapping("/security/decoy-ports/rotate")
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> rotateDecoyPorts() {
        return ResponseEntity.ok(ApiResponse.ok(decoyPortTrapService.rotate()));
    }

    @GetMapping("/security/segments")
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> blockedSegments() {
        List<Map<String, Object>> segments = new ArrayList<>();
        for (AttackGuardService.SegmentInfo s : attackGuardService.getBlockedSegments()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("segment", s.segment);
            item.put("block_count", s.blockCount);
            item.put("blocked_until", java.time.LocalDateTime.ofInstant(
                    java.time.Instant.ofEpochMilli(s.blockedUntil), java.time.ZoneId.systemDefault()).toString());
            item.put("blocked_seconds", s.blockedSeconds);
            segments.add(item);
        }
        return ResponseEntity.ok(ApiResponse.ok(segments));
    }

    @PostMapping("/security/segment-unblock")
    public ResponseEntity<ApiResponse<Void>> unblockSegment(@RequestBody Map<String, String> body) {
        String segment = body.get("segment");
        if (segment == null || segment.isBlank()) {
            return ResponseEntity.badRequest().body(ApiResponse.error(400, "\u7f3a\u5c11segment\u53c2\u6570"));
        }
        attackGuardService.unblockSegment(segment.trim());
        return ResponseEntity.ok(ApiResponse.ok("\u5df2\u89e3\u9664\u6bb5\u5c01\u7981", null));
    }

    @GetMapping("/security/attacker/{ip}/report")
    public ResponseEntity<ApiResponse<Map<String, Object>>> attackerReport(@PathVariable String ip) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("profile", threatIntelService.buildAttackerProfile(ip));
        result.put("report_markdown", threatIntelService.buildAbuseReport(ip));
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    @GetMapping("/security/attacks")
    public ResponseEntity<ApiResponse<Map<String, Object>>> attackLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        int safePage = Math.max(0, page);
        int safeSize = Math.min(Math.max(1, size), 100);
        List<Map<String, Object>> content = new ArrayList<>();
        long total = 0;
        java.util.List<String> geoWarmupIps = new ArrayList<>();
        try {
            Page<AttackLog> logs = attackLogRepository.findAllByOrderByCreatedAtDesc(PageRequest.of(safePage, safeSize));
            total = logs.getTotalElements();
            for (AttackLog a : logs.getContent()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("id", a.getId());
                m.put("ip", a.getIp());
                m.put("attack_type", a.getAttackType());
                m.put("path", a.getPath());
                m.put("payload", a.getPayload());
                m.put("user_agent", a.getUserAgent());
                m.put("method", a.getMethod());
                m.put("score", a.getScore());
                m.put("action", a.getAction());
                m.put("created_at", a.getCreatedAt() != null ? a.getCreatedAt().toString() : "");
                // IronWall v1.28.5: 攻击流水附带 IP 位置（缓存命中直接返回，未识别后台预热）
                m.put("geo", threatIntelService.geoFromCache(a.getIp()));
                if (m.get("geo") == null) geoWarmupIps.add(a.getIp());
                content.add(m);
            }
        } catch (Exception e) {
            log.warn("attack logs unavailable: {}", e.getMessage());
        }
        threatIntelService.warmUpGeoAsync(geoWarmupIps);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("content", content);
        result.put("totalElements", total);
        result.put("page", safePage);
        result.put("size", safeSize);
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    /** IronWall v1.28.5: 管理员按需实时定位单个 IP（带缓存）。 */
    @GetMapping("/security/ip-geo")
    public ResponseEntity<ApiResponse<Map<String, Object>>> ipGeo(@RequestParam String ip) {
        if (ip == null || ip.isBlank()) {
            return ResponseEntity.badRequest().body(ApiResponse.error(400, "\u7f3a\u5c11ip\u53c2\u6570"));
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ip", ip.trim());
        result.put("geo", threatIntelService.lookupGeo(ip.trim()));
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    @PostMapping("/security/unblock")
    public ResponseEntity<ApiResponse<Void>> unblockIp(@RequestBody Map<String, String> body) {
        String ip = body.get("ip");
        if (ip == null || ip.isBlank()) {
            return ResponseEntity.badRequest().body(ApiResponse.error(400, "缺少IP参数"));
        }
        attackGuardService.unblock(ip.trim());
        return ResponseEntity.ok(ApiResponse.ok("已解除封禁", null));
    }

    /**
     * IronWall v1.39.0: ——精确清理由 multipart 误报
     * （NULL字节截断 + 上传端点）导致的封禁与计分；存在真实攻击流水的 IP 一律保留封禁。
     */
    @PostMapping("/security/purge-upload-false-positives")
    public ResponseEntity<ApiResponse<Map<String, Object>>> purgeUploadFalsePositives() {
        List<String> purged = attackGuardService.purgeUploadFalsePositives();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("count", purged.size());
        result.put("ips", purged);
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    /**
     * IronWall v1.17.3: 管理面板一键手动封禁 IP。
     */
    @PostMapping("/security/block-ip")
    public ResponseEntity<ApiResponse<Map<String, Object>>> blockIp(@RequestBody Map<String, String> body) {
        String ip = body == null ? null : body.get("ip");
        if (ip == null || ip.isBlank()) {
            return ResponseEntity.badRequest().body(ApiResponse.error(400, "缺少ip参数"));
        }
        int minutes = 30;
        try {
            if (body.get("minutes") != null && !body.get("minutes").isBlank()) {
                minutes = Integer.parseInt(body.get("minutes").trim());
            }
        } catch (NumberFormatException e) {
            return ResponseEntity.badRequest().body(ApiResponse.error(400, "minutes参数无效"));
        }
        AttackGuardService.AttackRecord rec = attackGuardService.manualBlock(ip.trim(), minutes);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ip", rec.ip);
        result.put("score", rec.score);
        result.put("block_count", rec.blockCount);
        result.put("blocked_until", java.time.LocalDateTime.ofInstant(
                java.time.Instant.ofEpochMilli(rec.blockedUntil), java.time.ZoneId.systemDefault()).toString());
        result.put("blocked_seconds", Math.max(0, (rec.blockedUntil - System.currentTimeMillis()) / 1000));
        result.put("geo", threatIntelService.lookupGeo(rec.ip));
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    /** IronWall v1.47.3: admin view of share download rate-limit buckets (closed loop). */
    @GetMapping("/security/share-download-limits")
    public ResponseEntity<ApiResponse<Map<String, Object>>> shareDownloadLimits() {
        return ResponseEntity.ok(ApiResponse.ok(shareDownloadLimiter.snapshot()));
    }

    /** IronWall v1.47.3: admin reset of one bucket (by key) or all buckets. */
    @PostMapping("/security/share-download-limits/reset")
    public ResponseEntity<ApiResponse<Map<String, Object>>> resetShareDownloadLimits(
            @RequestBody(required = false) Map<String, String> body) {
        String key = body == null ? null : body.get("key");
        Map<String, Object> result = new LinkedHashMap<>();
        if (key != null && !key.isBlank()) {
            boolean cleared = shareDownloadLimiter.reset(key.trim());
            result.put("cleared", cleared);
            result.put("key", key.trim());
        } else {
            result.put("cleared", shareDownloadLimiter.resetAll());
        }
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    private List<Map<String, Object>> convertUsers(List<User> users) {
        List<Map<String, Object>> list = new ArrayList<>();
        for (User u : users) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", u.getId());
            m.put("username", u.getUsername());
            m.put("email", u.getEmail());
            m.put("role", u.getRole());
            m.put("user_status", u.getUserStatus());
            m.put("verification_status", u.getVerificationStatus());
            m.put("storage_used", u.getStorageUsed());
            m.put("storage_limit", u.getStorageLimit());
            m.put("upload_limit", u.getUploadLimit());
            m.put("avatar", u.getAvatar());
            m.put("user_code", u.getUserCode());
            m.put("verification_badge", u.getVerificationBadge());
            m.put("login_attempts", u.getLoginAttempts());
            m.put("created_at", u.getCreatedAt() != null ? u.getCreatedAt().toString() : "");
            list.add(m);
        }
        return list;
    }

    private List<Map<String, Object>> convertFiles(List<FileEntity> files) {
        List<Map<String, Object>> list = new ArrayList<>();
        Map<Long, User> userMap = resolveUsersByIds(files.stream()
                .map(FileEntity::getUserId).filter(Objects::nonNull).distinct().toList());
        for (FileEntity f : files) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", f.getId());
            m.put("filename", f.getFilename());
            m.put("original_name", f.getOriginalName());
            m.put("file_size", f.getFileSize());
            m.put("file_type", f.getFileType());
            m.put("mime_type", f.getMimeType());
            m.put("user_id", f.getUserId());
            m.put("username", ownerName(userMap, f.getUserId()));
            m.put("user_code", ownerCode(userMap, f.getUserId()));
            m.put("folder_id", f.getFolderId());
            m.put("is_shared", f.getIsShared());
            m.put("download_count", f.getDownloadCount());
            m.put("status", f.getStatus());
            m.put("created_at", f.getCreatedAt() != null ? f.getCreatedAt().toString() : "");
            list.add(m);
        }
        return list;
    }

    private List<Map<String, Object>> convertShares(List<Share> shares) {
        List<Map<String, Object>> list = new ArrayList<>();
        Map<Long, User> userMap = resolveUsersByIds(shares.stream()
                .map(Share::getUserId).filter(Objects::nonNull).distinct().toList());
        for (Share s : shares) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", s.getId());
            m.put("share_type", s.getShareType());
            m.put("file_id", s.getFileId());
            m.put("folder_id", s.getFolderId());
            m.put("share_code", s.getShareCode());
            m.put("download_limit", s.getDownloadLimit());
            m.put("download_count", s.getDownloadCount());
            m.put("user_id", s.getUserId());
            m.put("username", ownerName(userMap, s.getUserId()));
            m.put("user_code", ownerCode(userMap, s.getUserId()));
            m.put("status", s.getStatus());
            m.put("created_at", s.getCreatedAt() != null ? s.getCreatedAt().toString() : "");
            list.add(m);
        }
        return list;
    }

    /** IronWall v1.47.4: 批量解析用户（避免 N+1），缺失用户回退空字符串。 */
    private Map<Long, User> resolveUsersByIds(List<Long> userIds) {
        if (userIds == null || userIds.isEmpty()) {
            return Map.of();
        }
        Map<Long, User> map = new HashMap<>();
        for (User u : userRepository.findAllById(userIds)) {
            map.put(u.getId(), u);
        }
        return map;
    }

    private String ownerName(Map<Long, User> userMap, Long userId) {
        if (userId == null) return "";
        User u = userMap.get(userId);
        return u == null || u.getUsername() == null ? "" : u.getUsername();
    }

    private String ownerCode(Map<Long, User> userMap, Long userId) {
        if (userId == null) return "";
        User u = userMap.get(userId);
        return u == null || u.getUserCode() == null ? "" : u.getUserCode();
    }

    private List<Map<String, Object>> convertAnnouncements(List<Announcement> anns) {
        List<Map<String, Object>> list = new ArrayList<>();
        for (Announcement a : anns) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", a.getId());
            m.put("title", com.jdy.cloud.util.SecurityUtils.stripHtmlTags(a.getTitle()));
            m.put("content", com.jdy.cloud.util.SecurityUtils.stripHtmlTags(a.getContent()));
            m.put("created_by", a.getCreatedBy());
            m.put("status", a.getStatus());
            m.put("created_at", a.getCreatedAt() != null ? a.getCreatedAt().toString() : "");
            m.put("publish_at", a.getUpdatedAt() != null && "scheduled".equals(a.getStatus())
                    ? a.getUpdatedAt().toString() : "");
            list.add(m);
        }
        return list;
    }

    private List<Map<String, Object>> convertLogs(List<AuditLog> logs) {
        List<Map<String, Object>> list = new ArrayList<>();
        for (AuditLog l : logs) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", l.getId());
            m.put("user_id", l.getUserId());
            m.put("username", l.getUsername());
            m.put("action", l.getAction());
            m.put("target_type", l.getTargetType());
            m.put("target_id", l.getTargetId());
            m.put("target_name", l.getTargetName());
            m.put("detail", l.getDetail());
            m.put("time", l.getCreatedAt() != null ? l.getCreatedAt().toString() : "");
            m.put("ip", l.getIp());
            m.put("device", l.getDevice());
            m.put("status", l.getStatus());
            list.add(m);
        }
        return list;
    }

    @GetMapping("/users")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String keyword) {
        Page<User> users = adminService.getUsers(page, size, keyword);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("content", convertUsers(users.getContent()));
        result.put("totalElements", users.getTotalElements());
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    @GetMapping("/users/unverified")
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getUnverifiedUsers() {
        List<User> users = adminService.getUnverifiedUsers();
        return ResponseEntity.ok(ApiResponse.ok(convertUsers(users)));
    }

    @PostMapping("/users/{userId}/verify")
    public ResponseEntity<ApiResponse<Void>> verifyUser(@PathVariable Long userId,
                                                         @AuthenticationPrincipal UserPrincipal principal,
                                                         @RequestBody(required = false) Map<String, String> body) {
        String badge = (body != null && body.containsKey("badge")) ? body.get("badge") : "已认证";
        adminService.verifyUserWithBadge(userId, badge);
        String targetUsername = resolveTargetUsername(userId);
        auditLogService.logAdminAction(principal.getUserId(), "verify_user", "user", targetUsername, "认证用户 " + targetUsername + "，徽章: " + badge, "system");
        return ResponseEntity.ok(ApiResponse.ok("用户已认证", null));
    }

    @PostMapping("/users/{userId}/unverify")
    public ResponseEntity<ApiResponse<Void>> unverifyUser(@PathVariable Long userId,
                                                           @AuthenticationPrincipal UserPrincipal principal) {
        adminService.unverifyUser(userId);
        String targetUsername = resolveTargetUsername(userId);
        auditLogService.logAdminAction(principal.getUserId(), "unverify_user", "user", targetUsername, "取消认证用户 " + targetUsername, "system");
        return ResponseEntity.ok(ApiResponse.ok("已取消认证", null));
    }

    @PutMapping("/users/{userId}")
    public ResponseEntity<ApiResponse<Void>> updateUser(@PathVariable Long userId,
                                                         @RequestBody UpdateUserRequest request,
                                                         @AuthenticationPrincipal UserPrincipal principal) {
        User old = userRepository.findById(userId).orElse(null);
        adminService.updateUser(userId, request);
        String targetUsername = resolveTargetUsername(userId);

        // IronWall v1.11: 全量变更审计（存储空间/上传限额/角色/状态/邮箱/用户名），可追踪任何空间篡改
        StringBuilder detail = new StringBuilder("管理员更新用户 " + targetUsername + ":");
        if (request.getUserStatus() != null && !request.getUserStatus().equals(old == null ? null : old.getUserStatus())) {
            detail.append(" 状态 ").append(old == null ? "-" : old.getUserStatus()).append(" -> ").append(request.getUserStatus());
        }
        if (request.getStorageLimit() != null && (old == null || !request.getStorageLimit().equals(old.getStorageLimit()))) {
            detail.append(" 存储上限 ").append(old == null ? "-" : old.getStorageLimit()).append(" -> ").append(request.getStorageLimit());
        }
        if (request.getUploadLimit() != null && (old == null || !request.getUploadLimit().equals(old.getUploadLimit()))) {
            detail.append(" 上传限额 ").append(old == null ? "-" : old.getUploadLimit()).append(" -> ").append(request.getUploadLimit());
        }
        if (request.getRole() != null && !request.getRole().equals(old == null ? null : old.getRole())) {
            detail.append(" 角色 ").append(old == null ? "-" : old.getRole()).append(" -> ").append(request.getRole());
        }
        if (request.getEmail() != null && !request.getEmail().equals(old == null ? null : old.getEmail())) {
            detail.append(" 邮箱 ").append(old == null ? "-" : old.getEmail()).append(" -> ").append(request.getEmail());
        }
        if (request.getUsername() != null && !request.getUsername().equals(old == null ? null : old.getUsername())) {
            detail.append(" 用户名 ").append(old == null ? "-" : old.getUsername()).append(" -> ").append(request.getUsername());
        }
        String action = "update_user";
        if (request.getUserStatus() != null) {
            action = "banned".equals(request.getUserStatus()) ? "ban_user"
                    : ("active".equals(request.getUserStatus()) ? "unban_user" : "update_user");
        }
        auditLogService.logAdminAction(principal.getUserId(), action, "user", targetUsername, detail.toString(), "system");
        return ResponseEntity.ok(ApiResponse.ok("用户已更新", null));
    }


    @DeleteMapping("/users/{userId}")
    public ResponseEntity<ApiResponse<Void>> deleteUser(@PathVariable Long userId,
                                                          @AuthenticationPrincipal UserPrincipal principal) {
        String targetUsername = resolveTargetUsername(userId);
        auditLogService.logAdminAction(principal.getUserId(), "admin_delete_user", "user", targetUsername, "管理员删除了用户 " + targetUsername + " (ID: " + userId + ")", "system");
        adminService.deleteUser(userId);
        return ResponseEntity.ok(ApiResponse.ok("用户已删除", null));
    }

    @GetMapping("/files")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getFiles(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String keyword) {
        Page<FileEntity> files = adminService.getFiles(page, size, keyword);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("content", convertFiles(files.getContent()));
        result.put("totalElements", files.getTotalElements());
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    @PutMapping("/files/{fileId}/status")
    public ResponseEntity<ApiResponse<Void>> updateFileStatus(@PathVariable Long fileId,
                                                               @RequestBody Map<String, Integer> body) {
        int status = body.getOrDefault("status", 1);
        adminService.updateFileStatus(fileId, status);
        return ResponseEntity.ok(ApiResponse.ok("文件状态已更新", null));
    }

    @GetMapping("/shares")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getShares(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String keyword) {
        Page<Share> shares = adminService.getShares(page, size, keyword);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("content", convertShares(shares.getContent()));
        result.put("totalElements", shares.getTotalElements());
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    @PutMapping("/shares/{shareId}/status")
    public ResponseEntity<ApiResponse<Void>> updateShareStatus(@PathVariable Long shareId,
                                                                @RequestBody Map<String, Integer> body) {
        int status = body.getOrDefault("status", 1);
        adminService.updateShareStatus(shareId, status);
        return ResponseEntity.ok(ApiResponse.ok("分享状态已更新", null));
    }

    @GetMapping("/announcements")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getAnnouncements(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Page<Announcement> anns = adminService.getAnnouncements(page, size);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("content", convertAnnouncements(anns.getContent()));
        result.put("totalElements", anns.getTotalElements());
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    @PostMapping("/announcements")
    public ResponseEntity<ApiResponse<Map<String, Object>>> createAnnouncement(
            @AuthenticationPrincipal UserPrincipal principal,
            @Valid @RequestBody AnnouncementRequest request) {
        Announcement ann = adminService.createAnnouncement(principal.getUserId(), request);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", ann.getId());
        m.put("title", ann.getTitle());
        m.put("content", ann.getContent());
        m.put("status", ann.getStatus());
        m.put("created_at", ann.getCreatedAt() != null ? ann.getCreatedAt().toString() : "");
        m.put("publish_at", ann.getUpdatedAt() != null && "scheduled".equals(ann.getStatus())
                ? ann.getUpdatedAt().toString() : "");
        auditLogService.logAdminAction(principal.getUserId(), "create_announcement", "announcement", String.valueOf(ann.getId()), "发布公告: " + ann.getTitle(), "system");
        return ResponseEntity.ok(ApiResponse.ok(m));
    }

    @PutMapping("/announcements/{id}")
    public ResponseEntity<ApiResponse<Map<String, Object>>> updateAnnouncement(
            @PathVariable Long id,
            @Valid @RequestBody AnnouncementRequest request) {
        Announcement ann = adminService.updateAnnouncement(id, request);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", ann.getId());
        m.put("title", ann.getTitle());
        m.put("content", ann.getContent());
        m.put("status", ann.getStatus());
        m.put("created_at", ann.getCreatedAt() != null ? ann.getCreatedAt().toString() : "");
        m.put("publish_at", ann.getUpdatedAt() != null && "scheduled".equals(ann.getStatus())
                ? ann.getUpdatedAt().toString() : "");
        return ResponseEntity.ok(ApiResponse.ok(m));
    }

    @DeleteMapping("/announcements/{id}")
    public ResponseEntity<ApiResponse<Void>> deleteAnnouncement(@PathVariable Long id,
                                                                  @AuthenticationPrincipal UserPrincipal principal) {
        adminService.deleteAnnouncement(id);
        auditLogService.logAdminAction(principal.getUserId(), "delete_announcement", "announcement", String.valueOf(id), "删除了公告ID: " + id, "system");
        return ResponseEntity.ok(ApiResponse.ok("已删除", null));
    }

    @GetMapping("/logs")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getLogs(
            @RequestParam(required = false) String action,
            @RequestParam(required = false) Long userId,
            @RequestParam(required = false) String keyword,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        Page<AuditLog> logs = auditLogService.getLogs(action, userId, keyword, page, size);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("content", convertLogs(logs.getContent()));
        result.put("totalElements", logs.getTotalElements());
        result.put("totalPages", logs.getTotalPages());
        return ResponseEntity.ok(ApiResponse.ok(result));
    }

    @GetMapping("/download-stats")
    public ResponseEntity<ApiResponse<Map<String, Object>>> downloadStats() {
        return ResponseEntity.ok(ApiResponse.ok(adminService.getDownloadStats()));
    }

    @GetMapping("/settings")
    public ResponseEntity<ApiResponse<Map<String, String>>> getSettings() {
        log.info("getSettings called");
        Map<String, String> settings = new LinkedHashMap<>();
        String[] keys = {"site_name", "site_description", "allow_registration", "allow_all_file_types",
            "share_settings", "disabled_notice", "system_info", "recycle_retention_days",
            "smtp_host", "smtp_port", "smtp_username", "smtp_password", "smtp_from_name"};
        try {
            for (String key : keys) {
                systemConfigRepository.findByConfigKey(key)
                    .ifPresent(c -> settings.put(key, c.getConfigValue()));
            }
            log.info("getSettings success, loaded {} keys", settings.size());
        } catch (Exception e) {
            log.error("getSettings failed: {}", e.getMessage(), e);
            settings.put("site_name", "Classic Cloud");
            settings.put("site_description", "");
            settings.put("allow_registration", "true");
            settings.put("allow_all_file_types", "false");
            settings.put("share_settings", "{}");
            settings.put("disabled_notice", "");
            settings.put("system_info", "{}");
        }
        return ResponseEntity.ok(ApiResponse.ok(settings));
    }

    @PutMapping("/settings")
    public ResponseEntity<ApiResponse<Void>> updateSettings(@AuthenticationPrincipal UserPrincipal principal,
                                                              @RequestBody Map<String, String> settings) {
        log.info("updateSettings called with {} keys", settings.size());
        try {
            for (Map.Entry<String, String> entry : settings.entrySet()) {
                SystemConfig config = systemConfigRepository.findByConfigKey(entry.getKey())
                    .orElseGet(() -> { SystemConfig c = new SystemConfig(); c.setConfigKey(entry.getKey()); return c; });
                config.setConfigValue(entry.getValue());
                config.setUpdatedAt(java.time.LocalDateTime.now());
                systemConfigRepository.save(config);
            }
            auditLogService.logUpdateSettings(principal.getUserId(), "batch:" + settings.size() + " keys", "system");
            log.info("updateSettings success by userId={}", principal.getUserId());
        } catch (Exception e) {
            log.error("updateSettings failed: {}", e.getMessage(), e);
            return ResponseEntity.ok(ApiResponse.ok("partial_save", null));
        }
        return ResponseEntity.ok(ApiResponse.ok("设置已保存", null));
    }

    @PostMapping("/smtp/test")
    public ResponseEntity<ApiResponse<Void>> testSmtp(@RequestBody Map<String, String> body) {
        String testEmail = body.get("email");
        if (testEmail == null || testEmail.isBlank()) {
            return ResponseEntity.ok(ApiResponse.error(400, "请输入测试邮箱"));
        }
        try {
            verificationCodeService.sendCode(testEmail, "admin-test");
            return ResponseEntity.ok(ApiResponse.ok("测试邮件已发送", null));
        } catch (Exception e) {
            log.error("SMTP test failed: {}", e.getMessage());
            return ResponseEntity.ok(ApiResponse.error(500, "发送失败: " + e.getMessage()));
        }
    }


    @GetMapping("/appeals")
    public ResponseEntity<ApiResponse<List<AppealCenterService.AppealRecord>>> appeals() {
        return ResponseEntity.ok(ApiResponse.ok(appealCenterService.list()));
    }

    @PostMapping("/appeals/{id}/resolve")
    public ResponseEntity<ApiResponse<AppealCenterService.AppealRecord>> resolveAppeal(
            @PathVariable String id,
            @RequestBody Map<String, String> body) {
        String decision = body == null ? null : body.get("decision");
        String note = body == null ? null : body.get("note");
        AppealCenterService.AppealRecord record = appealCenterService.resolve(id, decision, note);
        if (record == null) {
            return ResponseEntity.ok(ApiResponse.error(400, "申诉不存在、已处理，或 decision 仅支持 processed/rejected"));
        }
        String message = Boolean.TRUE.equals(record.notified)
                ? "处理完成，已发送邮件通知申诉人"
                : "处理完成，未发送邮件通知：" + (record.notificationNote == null ? "申诉人未提供邮箱" : record.notificationNote);
        if (record.unbanNote != null && !record.unbanNote.isBlank()) {
            message += "；" + record.unbanNote;
        }
        return ResponseEntity.ok(ApiResponse.ok(message, record));
    }


    }
