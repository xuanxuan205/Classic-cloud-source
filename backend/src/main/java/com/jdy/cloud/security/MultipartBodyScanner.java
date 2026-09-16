package com.jdy.cloud.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.Part;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collection;

/**
 * IronWall v1.36.0: multipart 解析盲区闭环。
 *
 * 背景：引擎对 multipart/form-data 的 part 名、filename、字段值、文件头
 * 完全不检测，文件名 SQLi/穿越载荷直达应用层，是唯一的解析绕过点。
 *
 * 设计要点：
 * 1. 复用 Servlet 容器（Tomcat）的 getParts() 解析器——不手写 boundary 解析，
 * 天然兼容畸形 boundary 抛出、RFC5987 filename* 解码等边界；Tomcat 首次解析后
 * 缓存 part 列表，Spring 的 StandardMultipartHttpServletRequest 复用同一列表。
 * 2. Tomcat 的 ApplicationPart.getInputStream() 每次返回全新流（内存/临时文件均可
 * 重读），因此这里读取文件头不会消耗下游 MultipartFile 的内容。
 * 3. 读限而非拒限：字段值 ≤8KB、文件头 ≤4KB、part 数 ≤64。业务存在 850MB 大文件
 * 上传（max-file-size=850MB），故不采纳"单 part >50MB 直接 400"，只做有界读取，
 * 内存占用恒定。
 * 4. 检测管线与 JSON/form 完全一致：attackGuardService.detect() 自带 URL 解码、
 * 双重解码、JSON 转义归一化与 SQL 语义层。
 * 5. fail-open 铁律：detect 异常、单 part 读取异常一律跳过该 part，绝不误伤正常上传；
 * 仅 getParts() 整体解析失败（畸形 multipart）按协议异常 400 拒绝。
 * 6. IronWall v1.39.0：文件 part 头部先剥离控制字符（0x00-0x1F，保留 \t \n \r）
 * 再进检测管线——PNG/JPEG/PDF/ZIP 等二进制必然含 0x00，原文送检会确定性命中
 * NULL 字节规则，误杀全部良性上传；净化后良性二进制不再误报，而攻击者用
 * NULL/控制字符拼接隐藏的载荷会被还原为可见载荷继续命中。字段值保持原文检测。
 */
@Component
public class MultipartBodyScanner {

    /** 单请求 part 数上限，超出按协议异常拒绝。 */
    public static final int MAX_PARTS = 64;
    /** 非文件字段值最大检测字节数。 */
    public static final int MAX_FIELD_VALUE_SCAN = 8 * 1024;
    /** 文件 part 头部最大检测字节数（覆盖 PNG 魔数 + 紧随其后的脚本/标记对抗）。 */
    public static final int FILE_HEAD_SCAN = 4 * 1024;

    public enum Outcome { PASS, HIT, MALFORMED }

    /** 扫描结果：HIT 携带命中 Detection 与载荷片段，MALFORMED 携带原因（仅记日志用）。 */
    public static final class ScanResult {
        public final Outcome outcome;
        public final AttackGuardService.Detection detection;
        public final String snippet;

        private ScanResult(Outcome outcome, AttackGuardService.Detection detection, String snippet) {
            this.outcome = outcome;
            this.detection = detection;
            this.snippet = snippet;
        }

        public static ScanResult pass() { return new ScanResult(Outcome.PASS, null, null); }

        public static ScanResult hit(AttackGuardService.Detection detection, String snippet) {
            return new ScanResult(Outcome.HIT, detection, snippet);
        }

        public static ScanResult malformed(String reason) {
            return new ScanResult(Outcome.MALFORMED, null, reason);
        }
    }

    private final AttackGuardService attackGuardService;

    public MultipartBodyScanner(AttackGuardService attackGuardService) {
        this.attackGuardService = attackGuardService;
    }

    /**
     * 逐 part 提取文本并跑与 JSON/form 相同的检测管线。
     * 任何单 part 异常均 fail-open；getParts() 整体异常 → MALFORMED。
     */
    public ScanResult scan(HttpServletRequest request) {
        Collection<Part> parts;
        try {
            parts = request.getParts();
        } catch (IllegalStateException | IOException | ServletException e) {
            return ScanResult.malformed("multipart 解析失败: " + e.getClass().getSimpleName());
        }
        if (parts == null) {
            return ScanResult.pass();
        }
        if (parts.size() > MAX_PARTS) {
            return ScanResult.malformed("part 数量超限: " + parts.size());
        }
        String uri = request.getRequestURI();
        String userAgent = request.getHeader("User-Agent");
        String referer = request.getHeader("Referer");
        String cookie = request.getHeader("Cookie");
        for (Part part : parts) {
            String text;
            boolean filePart;
            try {
                text = extractPartText(part);
                filePart = part.getSubmittedFileName() != null && !part.getSubmittedFileName().isBlank();
            } catch (IOException e) {
                // 单 part 读取失败只跳过该 part，不阻断上传
                continue;
            }
            if (text == null || text.isEmpty()) {
                continue;
            }
            AttackGuardService.Detection detection;
            try {
                if (filePart) {
                    // IronWall v1.46.0: 文件 part 内容改走文件向检测器
                    // （可执行/脚本/SVG 净化，与 FileContentSafetyService 同源），
                    // 元数据（part 名/filename/Content-Type）仍走完整 WAF 管线。
                    detection = detectFilePart(part, text, uri, userAgent, referer, cookie);
                } else {
                    detection = attackGuardService.detect(null, text, uri, userAgent, referer, cookie);
                }
            } catch (Exception e) {
                // WAF 铁律：detect 异常 fail-open
                detection = null;
            }
            if (detection != null) {
                return ScanResult.hit(detection, text);
            }
        }
        return ScanResult.pass();
    }

    /**
     * IronWall v1.46.0: 文件 part 检测。
     * 元数据走完整 WAF 管线（文件名穿越/SQLi/伪后缀等）；文件内容只做文件向识别，
     * 避免通用 XSS 规则（<svg/<script 等参数注入特征）误杀合法文件内容，
     * 使 multipart 前置扫描与落盘后的 FileContentSafetyService 结论一致。
     */
    private AttackGuardService.Detection detectFilePart(Part part, String text, String uri, String userAgent, String referer, String cookie) {
        StringBuilder meta = new StringBuilder(128);
        appendLine(meta, part.getName());
        String fileName = part.getSubmittedFileName();
        appendLine(meta, fileName);
        appendLine(meta, part.getContentType());
        AttackGuardService.Detection metaHit;
        try {
            metaHit = attackGuardService.detect(null, meta.toString(), uri, userAgent, referer, cookie);
        } catch (Exception e) {
            metaHit = null;
        }
        if (metaHit != null) {
            return metaHit;
        }
        // 文件内容：剥离控制字符后的文本视图，只做文件向识别（与 FileContentSafetyService 同源），
        // 避免通用 XSS 参数注入特征（<svg 等）误杀合法文件内容，使前置扫描与落盘体检结论一致。
        String head = sanitizeFileHeadText(text);
        String scriptHit = FileContentSafetyService.detectFileHeadScript(head);
        if (scriptHit != null) {
            return new AttackGuardService.Detection(AttackGuardService.TYPE_XSS, scriptHit);
        }
        String ext = UploadPolicy.extensionOf(fileName);
        if ("svg".equals(ext)) {
            String svgHit = FileContentSafetyService.detectUnsafeSvgText(head);
            if (svgHit != null) {
                return new AttackGuardService.Detection(AttackGuardService.TYPE_XSS, svgHit);
            }
        }
        return null;
    }

    /** 文件头净化视图：剥离 0x00-0x1F（保留 \\t \\n \\r）后的文本（仅用于检测，不修改上传内容）。 */
    private static String sanitizeFileHeadText(String text) {
        if (text == null) {
            return "";
        }
        return text.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F]", "");
    }

    /**
     * part 检测文本 = name + submittedFileName + Content-Type + 字段值/文件头。
     * 文件名未显式归一化：detect() 内部已做 URL 解码、双重解码与 JSON 转义归一化，
     * 与 JSON/form 视图一致，避免重复归一化造成视图分叉。
     */
    private String extractPartText(Part part) throws IOException {
        StringBuilder sb = new StringBuilder(128);
        appendLine(sb, part.getName());
        String fileName = part.getSubmittedFileName();
        appendLine(sb, fileName);
        appendLine(sb, part.getContentType());
        boolean isFile = fileName != null && !fileName.isBlank();
        int limit = isFile ? FILE_HEAD_SCAN : MAX_FIELD_VALUE_SCAN;
        byte[] head = readHead(part, limit);
        if (head != null && head.length > 0) {
            // IronWall v1.39.0: 文件头净化仅作用于扫描视角，绝不修改上传内容本身
            sb.append(isFile ? sanitizeFileHead(head) : new String(head, StandardCharsets.UTF_8));
        }
        return sb.toString();
    }

    /**
     * IronWall v1.39.0: 文件头净化——剥离 0x00-0x1F 控制字符（保留 \t \n \r）后
     * 按 UTF-8 解码。只用于检测文本构造，上传内容不受影响。
     */
    private static String sanitizeFileHead(byte[] head) {
        if (head == null || head.length == 0) {
            return "";
        }
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(head.length);
        for (byte b : head) {
            int c = b & 0xFF;
            if (c >= 0x20 || c == '\t' || c == '\n' || c == '\r') {
                out.write(c);
            }
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    private static void appendLine(StringBuilder sb, String value) {
        if (value != null && !value.isEmpty()) {
            sb.append(value).append('\n');
        }
    }

    /** 有界读取：最多 limit 字节，杜绝大文件整块进内存。 */
    private byte[] readHead(Part part, int limit) throws IOException {
        try (InputStream in = part.getInputStream()) {
            byte[] buffer = new byte[limit];
            int total = 0;
            int read;
            while (total < limit && (read = in.read(buffer, total, limit - total)) != -1) {
                total += read;
            }
            if (total == 0) {
                return null;
            }
            if (total == limit) {
                return buffer;
            }
            byte[] trimmed = new byte[total];
            System.arraycopy(buffer, 0, trimmed, 0, total);
            return trimmed;
        }
    }
}
