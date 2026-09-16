package com.jdy.cloud.security;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ErrorReportValve;

/**
 * IronWall v1.28.9 / v1.28.11:
 * 容器级最小错误页。畸形 URI / 非法字符等请求在进入 Spring 之前由 Tomcat 直接拒绝，
 * 默认会返回带 Apache Tomcat 版本签名的 HTML 错误页（泄露技术栈）。
 * 本 Valve 统一返回最小 JSON 文案，不包含任何服务器信息。
 *
 * 修复：完整复刻 Tomcat 默认 ErrorReportValve 的守卫条件
 * （已提交 / 非错误状态 / 已有响应体 / 已报告过 一律不再写），
 * 杜绝在控制器已写 JSON 后追加第二段 JSON 的双写回归。
 */
public class MinimalErrorReportValve extends ErrorReportValve {

    @Override
    protected void report(Request request, Response response, Throwable throwable) {
        try {
            if (response.isCommitted()
                    || response.getStatus() < 400
                    || response.getContentWritten() > 0
                    || !response.setErrorReported()) {
                return;
            }
            int status = response.getStatus();
            String message = switch (status) {
                case 404 -> "资源不存在";
                case 405 -> "请求方法不支持";
                case 429 -> "请求过于频繁，请稍后再试";
                default -> "请求格式错误";
            };
            response.setContentType("application/json;charset=UTF-8");
            response.setCharacterEncoding("UTF-8");
            response.setHeader("Cache-Control", "no-store");
            response.getWriter().print("{\"success\":false,\"code\":" + status
                    + ",\"message\":\"" + message + "\"}");
        } catch (Exception e) {
            try {
                super.report(request, response, throwable);
            } catch (Exception ignored) {
                // 兜底：保持容器默认行为
            }
        }
    }
}