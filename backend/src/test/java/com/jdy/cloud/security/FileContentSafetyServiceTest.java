package com.jdy.cloud.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/** IronWall v1.28.4: 文件内容安全体检单元测试。 */
class FileContentSafetyServiceTest {

    private FileContentSafetyService service;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        service = new FileContentSafetyService();
    }

    private Path write(byte[] bytes) throws IOException {
        Path p = tempDir.resolve("f" + System.nanoTime() + ".bin");
        Files.write(p, bytes);
        return p;
    }

    private byte[] pngHead() {
        return new byte[]{(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, 'I', 'H', 'D', 'R'};
    }

    private byte[] mz() {
        return new byte[]{'M', 'Z', 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
    }

    @Test
    void peDisguisedAsImage_blockedForNormal() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(write(mz()), "photo.jpg", false);
        assertFalse(r.safe());
        assertTrue(r.detected().contains("PE"));
    }

    @Test
    void peDisguisedAsImage_blockedForAdmin() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(write(mz()), "photo.jpg", true);
        assertFalse(r.safe());
        assertTrue(r.detected().contains("PE"));
    }

    @Test
    void exeContentWithExeExt_allowedForAdmin() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(write(mz()), "tool.exe", true);
        assertTrue(r.safe());
    }

    @Test
    void phpDisguisedAsJpg_blockedForAdmin() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(write("<?php echo 'hi';".getBytes(StandardCharsets.UTF_8)), "pic.jpg", true);
        assertFalse(r.safe());
        assertTrue(r.detected().contains("PHP"));
    }

    @Test
    void phpWithPhpExt_allowedForAdmin() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(write("<?php echo 1;".getBytes(StandardCharsets.UTF_8)), "index.php", true);
        assertTrue(r.safe());
    }

    @Test
    void phpContent_blockedForNormalEvenWithPhpExt() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(write("<?php echo 1;".getBytes(StandardCharsets.UTF_8)), "index.php", false);
        assertFalse(r.safe());
        assertTrue(r.detected().contains("PHP"));
    }

    @Test
    void realPng_safeForNormal() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(write(pngHead()), "ok.png", false);
        assertTrue(r.safe());
    }

    @Test
    void jpgExtWithTextContent_blockedForNormal() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(write("just a text file".getBytes(StandardCharsets.UTF_8)), "fake.jpg", false);
        assertFalse(r.safe());
        assertTrue(r.reason().contains("不符"));
    }

    @Test
    void elfDetected() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(write(new byte[]{0x7F, 'E', 'L', 'F', 2, 1, 1, 0}), "a.jpg", false);
        assertFalse(r.safe());
        assertTrue(r.detected().contains("ELF"));
    }

    @Test
    void machoDetected() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(write(new byte[]{(byte) 0xFE, (byte) 0xED, (byte) 0xFA, (byte) 0xCE}), "a.jpg", false);
        assertFalse(r.safe());
        assertTrue(r.detected().contains("Mach-O"));
    }

    @Test
    void shellScriptDetected() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(write("#!/bin/bash\necho hi".getBytes(StandardCharsets.UTF_8)), "run.txt", false);
        assertFalse(r.safe());
        assertTrue(r.detected().contains("Shell"));
    }

    @Test
    void batchScriptDetected() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(write("@echo off\necho test".getBytes(StandardCharsets.UTF_8)), "a.jpg", false);
        assertFalse(r.safe());
        assertTrue(r.detected().contains("BAT"));
    }

    @Test
    void bomAndWhitespacePhpDetected() throws IOException {
        byte[] bom = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};
        byte[] rest = "  \n\t  <?php phpinfo();".getBytes(StandardCharsets.UTF_8);
        byte[] all = new byte[bom.length + rest.length];
        System.arraycopy(bom, 0, all, 0, bom.length);
        System.arraycopy(rest, 0, all, bom.length, rest.length);
        FileContentSafetyService.ScanResult r = service.scan(write(all), "x.jpg", true);
        assertFalse(r.safe());
        assertTrue(r.detected().contains("PHP"));
    }

    @Test
    void pdfValidForNormal() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(write("%PDF-1.7 content".getBytes(StandardCharsets.UTF_8)), "doc.pdf", false);
        assertTrue(r.safe());
    }

    @Test
    void zipValidForNormal() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(write(new byte[]{'P', 'K', 3, 4, 0, 0}), "pack.zip", false);
        assertTrue(r.safe());
    }

    @Test
    void adminZipNamedJpg_allowed() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(write(new byte[]{'P', 'K', 3, 4, 0, 0}), "x.jpg", true);
        assertTrue(r.safe());
    }

    // ==================== IronWall v1.45.0: 白名单新增后缀内容体检 ====================

    @Test
    void bmpValidForNormal() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(
                write("BM1234567890".getBytes(StandardCharsets.US_ASCII)), "photo.bmp", false);
        assertTrue(r.safe());
    }

    @Test
    void wavValidForNormal() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(
                write("RIFF1234WAVEfmt ".getBytes(StandardCharsets.US_ASCII)), "song.wav", false);
        assertTrue(r.safe());
    }

    @Test
    void movValidForNormal() throws IOException {
        byte[] mov = new byte[]{0, 0, 0, 0x18, 'f', 't', 'y', 'p', 'q', 't', ' ', ' ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        FileContentSafetyService.ScanResult r = service.scan(write(mov), "clip.mov", false);
        assertTrue(r.safe());
    }

    @Test
    void mkvValidForNormal() throws IOException {
        byte[] mkv = new byte[]{0x1A, 0x45, (byte) 0xDF, (byte) 0xA3, 0, 0, 0, 0};
        FileContentSafetyService.ScanResult r = service.scan(write(mkv), "video.mkv", false);
        assertTrue(r.safe());
    }

    @Test
    void svgValidForNormal() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(
                write("<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"
                        .getBytes(StandardCharsets.UTF_8)), "icon.svg", false);
        assertTrue(r.safe());
    }

    @Test
    void svgWithLeadingScript_blockedForNormal() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(
                write("<script>alert(1)</script>".getBytes(StandardCharsets.UTF_8)), "x.svg", false);
        assertFalse(r.safe());
        assertTrue(r.detected().contains("网页脚本"));
    }

    /** IronWall v1.47.9: XXE/实体声明注入对普通用户与管理员一律拦截。 */
    @Test
    void svgWithDoctypeEntity_blockedForNormalAndAdmin() throws IOException {
        String svg = "<?xml version=\"1.0\"?>"
                + "<!DOCTYPE svg [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
                + "<svg xmlns=\"http://www.w3.org/2000/svg\"><text>&xxe;</text></svg>";
        FileContentSafetyService.ScanResult normal = service.scan(
                write(svg.getBytes(StandardCharsets.UTF_8)), "x.svg", false);
        FileContentSafetyService.ScanResult admin = service.scan(
                write(svg.getBytes(StandardCharsets.UTF_8)), "x.svg", true);
        assertFalse(normal.safe());
        assertFalse(admin.safe());
    }

    /** IronWall v1.46.0: SVG 决策明确——纯矢量放行，脚本/事件/外链一律拦截。 */
    @Test
    void pureVectorSvgWithGradient_safeForNormalAndAdmin() throws IOException {
        String svg = "<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\">"
                + "<defs><linearGradient id=\"g\"><stop offset=\"0\" stop-color=\"#fff\"/></linearGradient></defs>"
                + "<rect x=\"1\" y=\"2\" width=\"100\" height=\"100\" fill=\"url(#g)\"/></svg>";
        assertTrue(service.scan(write(svg.getBytes(StandardCharsets.UTF_8)), "icon.svg", false).safe());
        assertTrue(service.scan(write(svg.getBytes(StandardCharsets.UTF_8)), "icon.svg", true).safe());
    }

    @Test
    void svgWithEventHandler_blockedForAdmin() throws IOException {
        String svg = "<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\">"
                + "<circle cx=\"1\" cy=\"1\" r=\"1\" onload=\"alert(1)\"/></svg>";
        FileContentSafetyService.ScanResult r = service.scan(
                write(svg.getBytes(StandardCharsets.UTF_8)), "x.svg", true);
        assertFalse(r.safe());
        assertTrue(r.detected().contains("事件"));
    }

    @Test
    void svgWithJavascriptProtocol_blockedForNormal() throws IOException {
        String svg = "<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\">"
                + "<a href=\"javascript:alert(1)\"><text>click</text></a></svg>";
        FileContentSafetyService.ScanResult r = service.scan(
                write(svg.getBytes(StandardCharsets.UTF_8)), "x.svg", false);
        assertFalse(r.safe());
        assertTrue(r.detected().contains("javascript"));
    }

    @Test
    void svgWithForeignObject_blockedForNormal() throws IOException {
        String svg = "<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\">"
                + "<foreignObject><body xmlns=\"http://www.w3.org/1999/xhtml\">x</body></foreignObject></svg>";
        FileContentSafetyService.ScanResult r = service.scan(
                write(svg.getBytes(StandardCharsets.UTF_8)), "x.svg", false);
        assertFalse(r.safe());
        assertTrue(r.detected().contains("外部对象"));
    }

    /** IronWall v1.47.0: 产品口径 27 个后缀用真实魔数字节逐一走整体检，全部放行（百分百可上传）。 */
    @Test
    void all27WhitelistExtensions_realMagicBytes_passForNormal() throws IOException {
        Map<String, byte[]> samples = new LinkedHashMap<>();
        byte[] pdf = "%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF".getBytes(StandardCharsets.UTF_8);
        samples.put("pdf", pdf);
        samples.put("doc", ole2());
        samples.put("docx", zipWith("[Content_Types].xml"));
        samples.put("xls", ole2());
        samples.put("xlsx", zipWith("[Content_Types].xml"));
        samples.put("ppt", ole2());
        samples.put("pptx", zipWith("[Content_Types].xml"));
        samples.put("txt", "hello world".getBytes(StandardCharsets.UTF_8));
        samples.put("md", "# 标题".getBytes(StandardCharsets.UTF_8));
        samples.put("csv", "a,b,c".getBytes(StandardCharsets.UTF_8));
        samples.put("jpg", jpegHead());
        samples.put("jpeg", jpegHead());
        samples.put("png", pngHead());
        samples.put("gif", concat("GIF89a".getBytes(StandardCharsets.UTF_8), new byte[8]));
        samples.put("bmp", concat(new byte[]{'B', 'M'}, new byte[12]));
        samples.put("webp", riff("WEBP"));
        samples.put("svg", "<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"><rect width=\"1\" height=\"1\"/></svg>"
                .getBytes(StandardCharsets.UTF_8));
        samples.put("mp3", "ID3\u0004\u0000\u0000\u0000\u0000\u0000\u0000".getBytes(StandardCharsets.ISO_8859_1));
        samples.put("wav", riff("WAVE"));
        samples.put("flac", concat("fLaC".getBytes(StandardCharsets.US_ASCII), new byte[8]));
        samples.put("mp4", concat(new byte[4], "ftypisom".getBytes(StandardCharsets.US_ASCII)));
        samples.put("mov", concat(new byte[4], "ftypqt  ".getBytes(StandardCharsets.US_ASCII)));
        samples.put("mkv", concat(new byte[]{0x1A, 0x45, (byte) 0xDF, (byte) 0xA3}, new byte[8]));
        samples.put("avi", concat("RIFF".getBytes(StandardCharsets.US_ASCII), new byte[4], "AVI LIST".getBytes(StandardCharsets.US_ASCII)));
        samples.put("zip", concat(new byte[]{'P', 'K', 3, 4}, new byte[8]));
        samples.put("7z", concat(new byte[]{0x37, 0x7A, (byte) 0xBC, (byte) 0xAF, 0x27, 0x1C}, new byte[8]));
        samples.put("rar", concat("Rar!\u001A\u0007\u0000".getBytes(StandardCharsets.ISO_8859_1), new byte[8]));

        for (Map.Entry<String, byte[]> e : samples.entrySet()) {
            FileContentSafetyService.ScanResult r = service.scan(write(e.getValue()), "sample." + e.getKey(), false);
            assertTrue(r.safe(), "后缀 ." + e.getKey() + " 的真实魔数应通过体检，实际拦截：" + r.reason());
        }
    }

    /** IronWall v1.47.0: 魔数伪装依然拦截（抽样保证收紧白名单没有放松内容体检）。 */
    @Test
    void disguisedContent_stillBlocked_afterWhitelistChange() throws IOException {
        // exe 伪装成 zip：压缩包内容必须 PK 魔数
        FileContentSafetyService.ScanResult exeAsZip = service.scan(write(mz()), "tool.zip", false);
        assertFalse(exeAsZip.safe());
        // 文本伪装成 jpg：图片必须真实光栅魔数
        FileContentSafetyService.ScanResult textAsJpg = service.scan(
                write("plain text".getBytes(StandardCharsets.UTF_8)), "fake.jpg", false);
        assertFalse(textAsJpg.safe());
        // 脚本伪装成 doc
        FileContentSafetyService.ScanResult phpAsDoc = service.scan(
                write("<?php echo 1;".getBytes(StandardCharsets.UTF_8)), "report.doc", false);
        assertFalse(phpAsDoc.safe());
    }

    private static byte[] ole2() {
        return concat(new byte[]{(byte) 0xD0, (byte) 0xCF, 0x11, (byte) 0xE0, (byte) 0xA1, (byte) 0xB1, 0x1A, (byte) 0xE1}, new byte[16]);
    }

    private static byte[] jpegHead() {
        return concat(new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0}, new byte[12]);
    }

    private static byte[] riff(String fourCc) {
        return concat("RIFF".getBytes(StandardCharsets.US_ASCII), new byte[4], fourCc.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) {
            total += p.length;
        }
        byte[] out = new byte[total];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }

    @Test
    void svgWithExternalHref_blockedForNormal() throws IOException {
        String svg = "<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\" "
                + "xmlns:xlink=\"http://www.w3.org/1999/xlink\">"
                + "<image xlink:href=\"https://evil.example.com/x.png\"/></svg>";
        FileContentSafetyService.ScanResult r = service.scan(
                write(svg.getBytes(StandardCharsets.UTF_8)), "x.svg", false);
        assertFalse(r.safe());
        assertTrue(r.detected().contains("外部资源"));
    }

    @Test
    void mdCsvTxtSafeForNormal() throws IOException {
        assertTrue(service.scan(write("# 标题".getBytes(StandardCharsets.UTF_8)), "readme.md", false).safe());
        assertTrue(service.scan(write("a,b,c".getBytes(StandardCharsets.UTF_8)), "data.csv", false).safe());
        assertTrue(service.scan(write("hello".getBytes(StandardCharsets.UTF_8)), "notes.txt", false).safe());
    }

    @Test
    void missingFile_failOpen() {
        FileContentSafetyService.ScanResult r = service.scan(tempDir.resolve("nope.bin"), "a.jpg", false);
        assertTrue(r.safe());
    }

    @Test
    void sorryRansomDoubleExt_blockedEvenForAdmin() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(write(pngHead()), "photo.jpg.sorry", true);
        assertFalse(r.safe());
        assertTrue(r.reason().contains("勒索"));
    }

    @Test
    void ransomNoteName_blocked() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(
                write("note".getBytes(StandardCharsets.UTF_8)), "HOW_TO_DECRYPT_FILES.txt", false);
        assertFalse(r.safe());
        assertTrue(r.reason().contains("赎金"));
    }

    @Test
    void lnkDetected() throws IOException {
        byte[] lnk = new byte[32];
        lnk[0] = 0x4C;
        lnk[4] = 0x01;
        lnk[5] = 0x14;
        lnk[6] = 0x02;
        lnk[8] = (byte) 0xC0;
        lnk[15] = 0x46;
        FileContentSafetyService.ScanResult r = service.scan(write(lnk), "shortcut.jpg", false);
        assertFalse(r.safe());
        assertTrue(r.detected().contains("LNK"));
    }

    @Test
    void pyInstallerDetected() throws IOException {
        byte[] b = new byte[]{0x4D, 0x45, 0x49, 0x0C, 0x0B, 0x0A, 0x0B, 0x0E};
        FileContentSafetyService.ScanResult r = service.scan(write(b), "app.jpg", false);
        assertFalse(r.safe());
        assertTrue(r.detected().contains("PyInstaller"));
    }

    @Test
    void autoItDetected() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(
                write("AU3!payload".getBytes(StandardCharsets.UTF_8)), "x.jpg", false);
        assertFalse(r.safe());
        assertTrue(r.detected().contains("AutoIt"));
    }

    @Test
    void macroDocxDisguised_blockedForAdmin() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(write(macroZip()), "report.docx", true);
        assertFalse(r.safe());
        assertTrue(r.detected().contains("macro"));
    }

    @Test
    void macroEnabledExt_allowedForAdmin() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(write(macroZip()), "report.xlsm", true);
        assertTrue(r.safe());
    }

    @Test
    void zipWithExeEntry_blockedForNormal() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(write(zipWith("setup.exe")), "files.zip", false);
        assertFalse(r.safe());
        assertTrue(r.reason().contains("压缩包"));
    }

    @Test
    void cleanZip_safeForNormal() throws IOException {
        FileContentSafetyService.ScanResult r = service.scan(write(zipWith("readme.txt")), "files.zip", false);
        assertTrue(r.safe());
    }

    private byte[] macroZip() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            zos.putNextEntry(new ZipEntry("word/vbaProject.bin"));
            zos.write(new byte[]{1, 2, 3});
            zos.closeEntry();
        }
        return baos.toByteArray();
    }

    private byte[] zipWith(String entryName) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            zos.putNextEntry(new ZipEntry(entryName));
            zos.write("hello".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }
        return baos.toByteArray();
    }
}
