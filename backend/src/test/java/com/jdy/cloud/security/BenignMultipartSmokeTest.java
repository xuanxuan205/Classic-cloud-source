package com.jdy.cloud.security;

import com.jdy.cloud.repository.AttackLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.Part;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.*;

/**
 * IronWall v1.39.0: CI 冒烟——真实检测管线（非 mock）下验证：
 * 1. 良性二进制文件头（含 0x00 的 PNG）不再误报（根因回归护栏）；
 * 2. 恶意文件名 / 文件头脚本载荷仍全量拦截；
 * 3. NULL/控制字符拼接隐藏载荷经净化后被还原命中（防护不降反升）；
 * 4. 文本字段值中的 NULL 字节仍按 语义拦截。
 * 本测试随 mvn test 进入 security-gate GAP=0 门禁。
 */
@ExtendWith(MockitoExtension.class)
class BenignMultipartSmokeTest {

    @Mock
    private AttackLogRepository attackLogRepository;

    private AttackGuardService guard;
    private MultipartBodyScanner scanner;

    @BeforeEach
    void setUp() throws Exception {
        guard = new AttackGuardService(attackLogRepository);
        for (String name : List.of("enabled", "operatorFamilyEnabled", "mysqlBuiltinEnabled", "semanticEnabled")) {
            java.lang.reflect.Field field = AttackGuardService.class.getDeclaredField(name);
            field.setAccessible(true);
            field.set(guard, true);
        }
        scanner = new MultipartBodyScanner(guard);
    }

    private HttpServletRequest requestWith(List<Part> parts) throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn("/api/auth/upload-avatar");
        when(request.getParts()).thenReturn(parts);
        return request;
    }

    private Part filePart(String name, String filename, String contentType, byte[] content) throws java.io.IOException {
        Part part = mock(Part.class);
        when(part.getName()).thenReturn(name);
        when(part.getSubmittedFileName()).thenReturn(filename);
        when(part.getContentType()).thenReturn(contentType);
        when(part.getInputStream()).thenReturn(new ByteArrayInputStream(content));
        return part;
    }

    private Part fieldPart(String name, String value) throws java.io.IOException {
        return filePart(name, null, null, value.getBytes(StandardCharsets.UTF_8));
    }

    private byte[] realPngHead() {
        return new byte[]{(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0x0D,
                0x49, 0x48, 0x44, 0x52, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 0x1F, 0x15, (byte) 0xC4};
    }

    @Test
    void benignPngMultipartShouldPassRealDetectPipeline() throws Exception {
        HttpServletRequest request = requestWith(List.of(
                filePart("avatar", "photo.png", "image/png", realPngHead())));

        MultipartBodyScanner.ScanResult result = scanner.scan(request);

        assertEquals(MultipartBodyScanner.Outcome.PASS, result.outcome,
                "根因护栏：含 0x00 的良性 PNG 文件头必须放行");
    }

    @Test
    void benignChunkUploadWithBinaryHeadShouldPassRealDetectPipeline() throws Exception {
        byte[] zipLike = new byte[]{0x50, 0x4B, 3, 4, 0, 0, 8, 0, 0x11, 0x22, 0x33, 0x44};
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn("/api/files/upload/chunk");
        List<Part> parts = List.of(
                filePart("file", "part-1.bin", "application/octet-stream", zipLike));
        when(request.getParts()).thenReturn(parts);

        MultipartBodyScanner.ScanResult result = scanner.scan(request);

        assertEquals(MultipartBodyScanner.Outcome.PASS, result.outcome);
    }

    @Test
    void maliciousFilenameShouldStillHit() throws Exception {
        HttpServletRequest request = requestWith(List.of(
                filePart("avatar", "admin' OR '1'='1.png", "image/png", realPngHead())));

        MultipartBodyScanner.ScanResult result = scanner.scan(request);

        assertEquals(MultipartBodyScanner.Outcome.HIT, result.outcome);
        assertEquals(AttackGuardService.TYPE_SQL, result.detection.type);
    }

    @Test
    void traversalFilenameShouldStillHit() throws Exception {
        RuleAssumptions.requireRule("patterns.traversal");
        HttpServletRequest request = requestWith(List.of(
                filePart("file", "../../../etc/passwd", "text/plain",
                        "hello".getBytes(StandardCharsets.UTF_8))));

        MultipartBodyScanner.ScanResult result = scanner.scan(request);

        assertEquals(MultipartBodyScanner.Outcome.HIT, result.outcome);
        assertEquals(AttackGuardService.TYPE_TRAVERSAL, result.detection.type);
    }

    @Test
    void fileHeadScriptPayloadShouldStillHit() throws Exception {
        HttpServletRequest request = requestWith(List.of(
                filePart("avatar", "photo.png", "image/png",
                        "<script>alert(document.cookie)</script>".getBytes(StandardCharsets.UTF_8))));

        MultipartBodyScanner.ScanResult result = scanner.scan(request);

        assertEquals(MultipartBodyScanner.Outcome.HIT, result.outcome);
        assertEquals(AttackGuardService.TYPE_XSS, result.detection.type);
    }

    @Test
    void nullByteHiddenScriptShouldBeRevealedAndHit() throws Exception {
        HttpServletRequest request = requestWith(List.of(
                filePart("avatar", "photo.png", "image/png",
                        "<scr\0ipt>alert(1)</scr\0ipt>".getBytes(StandardCharsets.UTF_8))));

        MultipartBodyScanner.ScanResult result = scanner.scan(request);

        assertEquals(MultipartBodyScanner.Outcome.HIT, result.outcome,
                "控制字符拼接隐藏的载荷净化后必须还原命中");
        assertEquals(AttackGuardService.TYPE_XSS, result.detection.type);
    }

    @Test
    void fieldValueNullByteShouldStillHit() throws Exception {
        HttpServletRequest request = requestWith(List.of(
                fieldPart("nickname", "bad\u0000value")));

        MultipartBodyScanner.ScanResult result = scanner.scan(request);

        assertEquals(MultipartBodyScanner.Outcome.HIT, result.outcome,
                "语义保留：文本字段值中的 NULL 字节仍按截断探测拦截");
        assertNotNull(result.detection);
    }
}
