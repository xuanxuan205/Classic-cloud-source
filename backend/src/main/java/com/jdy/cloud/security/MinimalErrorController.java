package com.jdy.cloud.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * IronWall v1.28.11: 统一最小 JSON 错误响应。
 * 畸形分享码 / 下载 ID 等请求在 Spring MVC 参数绑定阶段被拒绝时，
 * 默认 Whitelabel 错误页会泄露 Spring/Tomcat 技术栈指纹。
 * 本控制器接管 /error，任何错误都返回不含框架签名的最小 JSON。
 */
@RestController
public class MinimalErrorController implements ErrorController {

    @RequestMapping("/error")
    public Map<String, Object> handleError(HttpServletRequest request, HttpServletResponse response) {
        Integer status = (Integer) request.getAttribute("jakarta.servlet.error.status_code");
        int code = status == null ? 400 : status;
        String message = switch (code) {
            case 400 -> "请求格式错误";
            case 401 -> "未授权";
            case 403 -> "拒绝访问";
            case 404 -> "资源不存在";
            case 405 -> "请求方法不支持";
            case 429 -> "请求过于频繁，请稍后再试";
            default -> "请求处理失败";
        };
        response.setStatus(code);
        response.setCharacterEncoding("UTF-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", false);
        body.put("code", code);
        body.put("message", message);
        return body;
    }
}