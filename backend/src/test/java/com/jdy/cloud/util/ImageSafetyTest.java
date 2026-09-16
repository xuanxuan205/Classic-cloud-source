package com.jdy.cloud.util;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IronWall v1.8: 头像图片魔数校验与重编码兜底。
 * 覆盖 AWT 可用与不可用两条路径：reencodeToPng 不抛异常，detectRasterFormat 拒绝非光栅内容。
 */
class ImageSafetyTest {

    private static final byte[] PNG_1x1 = new byte[]{
            (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x08, 0x02, 0x00, 0x00, 0x00, (byte) 0x90, 0x77, 0x53, (byte) 0xDE,
            0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54,
            0x08, (byte) 0xD7, 0x63, (byte) 0xF8, (byte) 0xCF, (byte) 0xC0, 0x00, 0x00,
            0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, (byte) 0xAE, 0x42, 0x60, (byte) 0x82
    };

    @Test
    void detectRasterFormat_shouldAcceptRealImages() {
        assertEquals("png", ImageSafety.detectRasterFormat(PNG_1x1));
        assertEquals("jpeg", ImageSafety.detectRasterFormat(new byte[]{
                (byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0, 0, 1, 2, 3, 4, 5, 6, 7}));
        assertEquals("gif", ImageSafety.detectRasterFormat(
                "GIF89a123456".getBytes(StandardCharsets.US_ASCII)));
        assertEquals("webp", ImageSafety.detectRasterFormat(
                "RIFF1234WEBP".getBytes(StandardCharsets.US_ASCII)));
        // IronWall v1.45.0: BMP 白名单放行依赖 BM 魔数识别
        assertEquals("bmp", ImageSafety.detectRasterFormat(
                "BM1234567890".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void detectRasterFormat_shouldRejectSvgAndScripts() {
        assertNull(ImageSafety.detectRasterFormat(
                "<svg onload=alert(1)></svg>".getBytes(StandardCharsets.UTF_8)));
        assertNull(ImageSafety.detectRasterFormat(
                "<script>alert(document.cookie)</script>".getBytes(StandardCharsets.UTF_8)));
        assertNull(ImageSafety.detectRasterFormat(
                "GIF89a".getBytes(StandardCharsets.US_ASCII)));
        assertNull(ImageSafety.detectRasterFormat(null));
        assertNull(ImageSafety.detectRasterFormat(new byte[0]));
    }

    @Test
    void reencodeToPng_shouldNeverThrowAndSanitizePng() {
        // AWT 可用时返回重编码 PNG；AWT 缺失时返回 null，由调用方走魔数兜底。两者都不应抛异常。
        byte[] out = ImageSafety.reencodeToPng(PNG_1x1);
        if (out != null) {
            assertEquals("png", ImageSafety.detectRasterFormat(out));
        }
        assertNull(ImageSafety.reencodeToPng(null));
        assertNull(ImageSafety.reencodeToPng(new byte[0]));
        assertNull(ImageSafety.reencodeToPng(
                "<svg onload=1>".getBytes(StandardCharsets.UTF_8)));
    }
}