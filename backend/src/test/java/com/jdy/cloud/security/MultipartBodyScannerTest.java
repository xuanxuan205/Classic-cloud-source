package com.jdy.cloud.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.Part;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * IronWall v1.36.0: multipart 解析盲区闭环——扫描器契约测试。
 * 覆盖：文件名 SQLi / 穿越 / 双重编码 / 字段值 XSS / 文件头载荷 / 良性放行 /
 * part 超量 / 解析异常 / 单 part 读取失败 fail-open / 文件头读限。
 */
@ExtendWith(MockitoExtension.class)
class MultipartBodyScannerTest {

    @Mock private AttackGuardService attackGuardService;
    @Mock private HttpServletRequest request;

    private MultipartBodyScanner scanner;

    @BeforeEach
    void setUp() {
        scanner = new MultipartBodyScanner(attackGuardService);
        lenient().when(request.getRequestURI()).thenReturn("/api/auth/upload-avatar");
    }

    private Part filePart(String name, String filename, String contentType, byte[] content) throws IOException {
        Part part = mock(Part.class);
        when(part.getName()).thenReturn(name);
        when(part.getSubmittedFileName()).thenReturn(filename);
        when(part.getContentType()).thenReturn(contentType);
        when(part.getInputStream()).thenReturn(new ByteArrayInputStream(content));
        return part;
    }

    private Part fieldPart(String name, String value) throws IOException {
        return filePart(name, null, null, value.getBytes(StandardCharsets.UTF_8));
    }

    /** 仅用于超量 part 用例：扫描器在读取任何 part 前即返回 MALFORMED，故 stub 一律宽松。 */
    private Part lenientFieldPart(String name, String value) throws IOException {
        Part part = mock(Part.class);
        lenient().when(part.getName()).thenReturn(name);
        lenient().when(part.getSubmittedFileName()).thenReturn(null);
        lenient().when(part.getContentType()).thenReturn(null);
        lenient().when(part.getInputStream())
                .thenReturn(new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8)));
        return part;
    }

    private byte[] png() {
        return new byte[]{(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0};
    }

    @Test
    void maliciousFilenameShouldHit() throws Exception {
        List<Part> parts = List.of(filePart("avatar", "admin' OR '1'='1.png", "image/png", png()));
        when(request.getParts()).thenReturn(parts);
        when(attackGuardService.detect(any(), any(), any(), any(), any(), any()))
                .thenReturn(new AttackGuardService.Detection(AttackGuardService.TYPE_SQL, "admin' OR '1'='1.png"));

        MultipartBodyScanner.ScanResult result = scanner.scan(request);

        assertEquals(MultipartBodyScanner.Outcome.HIT, result.outcome);
        assertEquals(AttackGuardService.TYPE_SQL, result.detection.type);
        verify(attackGuardService).detect(isNull(), contains("admin' OR '1'='1.png"),
                eq("/api/auth/upload-avatar"), any(), any(), any());
    }

    @Test
    void traversalFilenameShouldHit() throws Exception {
        List<Part> parts = List.of(filePart("file", "../../../etc/passwd", "text/plain",
                "x".getBytes(StandardCharsets.UTF_8)));
        when(request.getParts()).thenReturn(parts);
        when(attackGuardService.detect(any(), any(), any(), any(), any(), any()))
                .thenReturn(new AttackGuardService.Detection(AttackGuardService.TYPE_TRAVERSAL, "../../../etc/passwd"));

        MultipartBodyScanner.ScanResult result = scanner.scan(request);

        assertEquals(MultipartBodyScanner.Outcome.HIT, result.outcome);
    }

    @Test
    void doubleEncodedFilenameShouldHit() throws Exception {
        List<Part> parts = List.of(filePart("file", "%2527%2520OR%25201%253D1", "text/plain",
                "x".getBytes(StandardCharsets.UTF_8)));
        when(request.getParts()).thenReturn(parts);
        when(attackGuardService.detect(any(), any(), any(), any(), any(), any()))
                .thenReturn(new AttackGuardService.Detection(AttackGuardService.TYPE_SQL, "%2527"));

        MultipartBodyScanner.ScanResult result = scanner.scan(request);

        assertEquals(MultipartBodyScanner.Outcome.HIT, result.outcome);
    }

    @Test
    void fieldValueXssShouldHit() throws Exception {
        List<Part> parts = List.of(fieldPart("nickname", "<script>alert(1)</script>"));
        when(request.getParts()).thenReturn(parts);
        when(attackGuardService.detect(any(), any(), any(), any(), any(), any()))
                .thenReturn(new AttackGuardService.Detection(AttackGuardService.TYPE_XSS, "<script>alert(1)</script>"));

        MultipartBodyScanner.ScanResult result = scanner.scan(request);

        assertEquals(MultipartBodyScanner.Outcome.HIT, result.outcome);
    }

    @Test
    void fileHeadPayloadShouldHit() throws Exception {
        List<Part> parts = List.of(filePart("avatar", "photo.png", "image/png",
                "<script>alert(document.cookie)</script>".getBytes(StandardCharsets.UTF_8)));
        when(request.getParts()).thenReturn(parts);
        when(attackGuardService.detect(any(), any(), any(), any(), any(), any()))
                .thenReturn(new AttackGuardService.Detection(AttackGuardService.TYPE_XSS, "<script>"));

        MultipartBodyScanner.ScanResult result = scanner.scan(request);

        assertEquals(MultipartBodyScanner.Outcome.HIT, result.outcome);
    }

    @Test
    void benignUploadShouldPass() throws Exception {
        List<Part> parts = List.of(filePart("avatar", "photo.png", "image/png", png()));
        when(request.getParts()).thenReturn(parts);
        when(attackGuardService.detect(any(), any(), any(), any(), any(), any())).thenReturn(null);

        MultipartBodyScanner.ScanResult result = scanner.scan(request);

        assertEquals(MultipartBodyScanner.Outcome.PASS, result.outcome);
    }

    @Test
    void tooManyPartsShouldBeMalformed() throws Exception {
        List<Part> parts = new ArrayList<>();
        for (int i = 0; i < MultipartBodyScanner.MAX_PARTS + 1; i++) {
            parts.add(lenientFieldPart("f" + i, "v" + i));
        }
        when(request.getParts()).thenReturn(parts);

        MultipartBodyScanner.ScanResult result = scanner.scan(request);

        assertEquals(MultipartBodyScanner.Outcome.MALFORMED, result.outcome);
        verify(attackGuardService, never()).detect(any(), any(), any(), any(), any(), any());
    }

    @Test
    void parseFailureShouldBeMalformed() throws Exception {
        when(request.getParts()).thenThrow(new IllegalStateException("malformed boundary"));

        MultipartBodyScanner.ScanResult result = scanner.scan(request);

        assertEquals(MultipartBodyScanner.Outcome.MALFORMED, result.outcome);
    }

    @Test
    void singlePartReadFailureShouldFailOpen() throws Exception {
        Part broken = mock(Part.class);
        when(broken.getName()).thenReturn("avatar");
        when(broken.getSubmittedFileName()).thenReturn("photo.png");
        when(broken.getInputStream()).thenThrow(new IOException("read fail"));
        when(request.getParts()).thenReturn(List.of(broken));

        MultipartBodyScanner.ScanResult result = scanner.scan(request);

        assertEquals(MultipartBodyScanner.Outcome.PASS, result.outcome);
    }

    @Test
    void fileHeadReadShouldBeBoundedTo4K() throws Exception {
        byte[] content = new byte[10 * 1024];
        java.util.Arrays.fill(content, (byte) 'A');
        byte[] marker = "<script>MALICIOUS</script>".getBytes(StandardCharsets.UTF_8);
        System.arraycopy(marker, 0, content, 5 * 1024, marker.length);
        List<Part> parts = List.of(filePart("avatar", "photo.png", "image/png", content));
        when(request.getParts()).thenReturn(parts);
        when(attackGuardService.detect(any(), any(), any(), any(), any(), any())).thenReturn(null);

        scanner.scan(request);

        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(attackGuardService).detect(isNull(), bodyCaptor.capture(), any(), any(), any(), any());
        assertFalse(bodyCaptor.getValue().contains("MALICIOUS"));
    }
}
