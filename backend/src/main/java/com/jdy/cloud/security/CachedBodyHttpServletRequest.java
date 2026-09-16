package com.jdy.cloud.security;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * 缓存请求体的包装器：仅用于 JSON/表单等小体积请求体的安全扫描，multipart 不包装。
 *
 * IronWall v1.18: 新增按声明 charset 解码的 getBodyAsString(String)，
 * 使检测层与 Jackson 的解码视图一致，堵住 UTF-16/UTF-32 编码绕过。
 */
public class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

    private final byte[] cachedBody;

    public CachedBodyHttpServletRequest(HttpServletRequest request) throws IOException {
        super(request);
        this.cachedBody = request.getInputStream().readAllBytes();
    }

    @Override
    public ServletInputStream getInputStream() {
        ByteArrayInputStream in = new ByteArrayInputStream(cachedBody);
        return new ServletInputStream() {
            @Override
            public boolean isFinished() { return in.available() == 0; }

            @Override
            public boolean isReady() { return true; }

            @Override
            public void setReadListener(ReadListener readListener) { }

            @Override
            public int read() { return in.read(); }
        };
    }

    @Override
    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
    }

    public byte[] getCachedBody() {
        return cachedBody;
    }

    public String getBodyAsString() {
        return new String(cachedBody, StandardCharsets.UTF_8);
    }

    /**
     * IronWall v1.18: 按请求头声明的 charset 解码请求体。
     * 解码失败返回 null，由调用方按协议异常处理。
     */
    public String getBodyAsString(String charset) {
        try {
            Charset cs = charset == null || charset.isBlank()
                    ? StandardCharsets.UTF_8
                    : Charset.forName(charset.trim());
            return new String(cachedBody, cs);
        } catch (Exception e) {
            return null;
        }
    }
}