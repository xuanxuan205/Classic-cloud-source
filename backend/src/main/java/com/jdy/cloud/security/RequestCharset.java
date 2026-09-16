package com.jdy.cloud.security;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * IronWall v1.18 字符集归一化工具：
 * 检测层必须与 Spring/Jackson 的解码视图一致，否则 UTF-16/UTF-32 编码载荷
 * 会以原始字节形式绕过正则检测（第 19 轮 漏洞）。
 *
 * 三族分类：
 * SAFE: 常见合法编码，按声明解码后检测，不额外拒绝；
 * ANOMALOUS: UTF-16/UTF-32 系列，按声明解码后检测，命中载荷走 4440，
 * 未命中也按协议异常 415 拒绝；
 * REJECT: 罕见/未知编码，直接 415 拒绝并记分，压缩探测空间。
 */
public final class RequestCharset {

    public enum Family { SAFE, ANOMALOUS, REJECT }

    private RequestCharset() {
    }

    /**
     * 从 Content-Type 头解析 charset（兼容 charset=X 与 charset="X" 两种写法），
     * 未声明时返回 null（由调用方按 UTF-8 默认处理）。
     */
    public static String extractCharset(String contentType) {
        if (contentType == null || contentType.isBlank()) return null;
        String lower = contentType.toLowerCase(Locale.ROOT);
        int idx = lower.indexOf("charset=");
        if (idx < 0) return null;
        String rest = contentType.substring(idx + "charset=".length()).trim();
        if (rest.isEmpty()) return null;
        if (rest.charAt(0) == '"') {
            int end = rest.indexOf('"', 1);
            if (end > 0) return rest.substring(1, end).trim();
            return rest.substring(1).trim();
        }
        int end = rest.indexOf(';');
        return (end >= 0 ? rest.substring(0, end) : rest).trim();
    }

    public static Family classify(String charset) {
        if (charset == null || charset.isBlank()) return Family.SAFE;
        String name = charset.trim().toLowerCase(Locale.ROOT)
                .replace("_", "-");
        switch (name) {
            case "utf-8":
            case "utf8":
            case "us-ascii":
            case "ascii":
            case "iso-8859-1":
            case "latin1":
            case "latin-1":
            case "windows-1252":
            case "cp1252":
            case "gbk":
            case "gb2312":
            case "gb18030":
                return Family.SAFE;
            case "utf-16":
            case "utf-16le":
            case "utf-16be":
            case "utf-32":
            case "utf-32le":
            case "utf-32be":
                return Family.ANOMALOUS;
            default:
                return Family.REJECT;
        }
    }

    /**
     * 按声明 charset 解码请求体，并剥离 UTF-16/32 的 BOM（U+FEFF）。
     * 解码失败返回 null，由调用方按协议异常处理。
     */
    public static String decode(byte[] bytes, String charset) {
        if (bytes == null) return null;
        try {
            String out = new String(bytes, resolveCharset(charset));
            if (!out.isEmpty() && out.charAt(0) == '\uFEFF') {
                out = out.substring(1);
            }
            return out;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * IronWall v1.18.1: 无 charset 声明时嗅探 BOM，与 Jackson 的自动编码探测保持一致——
     * 攻击者发 UTF-16/32 字节流 + BOM 但不声明 charset 时，检测层同样要按 BOM 解码，
     * 否则出现"解码视图盲区"（Jackson 按 BOM 还原载荷，检测层按 UTF-8 看乱码）。
     * 返回 null 表示无 BOM 或 UTF-8 BOM。
     */
    public static String sniffBomCharset(byte[] bytes) {
        if (bytes == null || bytes.length < 2) return null;
        if (bytes.length >= 4) {
            if ((bytes[0] & 0xFF) == 0xFF && (bytes[1] & 0xFF) == 0xFE
                    && bytes[2] == 0 && bytes[3] == 0) {
                return "UTF-32LE";
            }
            if (bytes[0] == 0 && bytes[1] == 0
                    && (bytes[2] & 0xFF) == 0xFE && (bytes[3] & 0xFF) == 0xFF) {
                return "UTF-32BE";
            }
        }
        if ((bytes[0] & 0xFF) == 0xFF && (bytes[1] & 0xFF) == 0xFE) {
            return "UTF-16LE";
        }
        if ((bytes[0] & 0xFF) == 0xFE && (bytes[1] & 0xFF) == 0xFF) {
            return "UTF-16BE";
        }
        if (bytes.length >= 3 && (bytes[0] & 0xFF) == 0xEF && (bytes[1] & 0xFF) == 0xBB
                && (bytes[2] & 0xFF) == 0xBF) {
            return "UTF-8";
        }
        return null;
    }

    /**
     * charset 名称归一化：把 classify 白名单中的别名映射为 Java 标准字符集，
     * 避免 Charset.forName 对别名不支持导致误拒绝合法客户端。
     */
    private static Charset resolveCharset(String name) {
        if (name == null || name.isBlank()) return StandardCharsets.UTF_8;
        String n = name.trim().toLowerCase(Locale.ROOT).replace("_", "-");
        switch (n) {
            case "utf-8":
            case "utf8":
                return StandardCharsets.UTF_8;
            case "us-ascii":
            case "ascii":
                return StandardCharsets.US_ASCII;
            case "iso-8859-1":
            case "latin1":
            case "latin-1":
                return StandardCharsets.ISO_8859_1;
            case "windows-1252":
            case "cp1252":
                return Charset.forName("windows-1252");
            case "utf-16":
                return StandardCharsets.UTF_16;
            case "utf-16le":
                return StandardCharsets.UTF_16LE;
            case "utf-16be":
                return StandardCharsets.UTF_16BE;
            case "utf-32":
            case "utf-32be":
                return Charset.forName("UTF-32BE");
            case "utf-32le":
                return Charset.forName("UTF-32LE");
            default:
                return Charset.forName(name.trim());
        }
    }
}