package com.jdy.cloud.controller;

import com.jdy.cloud.dto.ApiResponse;
import com.jdy.cloud.service.FeedbackService;
import com.jdy.cloud.util.ClientIpUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * IronWall v1.27.0: 意见反馈（公开提交，邮件通知官方管理员邮箱）。
 */
@RestController
@RequestMapping("/api/feedback")
@RequiredArgsConstructor
public class FeedbackController {

    private final FeedbackService feedbackService;

    @PostMapping
    public ResponseEntity<ApiResponse<Void>> submit(@RequestBody(required = false) Map<String, String> body,
                                                    HttpServletRequest request) {
        String ip = ClientIpUtils.getClientIp(request);
        String contact = body == null ? null : body.get("contact");
        String content = body == null ? null : body.get("content");
        String code = feedbackService.submit(ip, contact, content);
        switch (code) {
            case "TOO_FREQUENT":
                return ResponseEntity.status(429).body(ApiResponse.error(429, "反馈提交过于频繁，请稍后再试。"));
            case "INVALID":
                return ResponseEntity.badRequest().body(ApiResponse.error(400, "反馈内容至少需要 5 个字。"));
            case "DISABLED":
                return ResponseEntity.status(503).body(ApiResponse.error(503, "反馈功能暂未开放。"));
            default:
                return ResponseEntity.ok(ApiResponse.ok("反馈已提交，感谢您的意见！", null));
        }
    }
}
