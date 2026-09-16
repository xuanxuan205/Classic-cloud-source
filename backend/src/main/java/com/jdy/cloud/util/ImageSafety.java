package com.jdy.cloud.util;

/**
 * IronWall v1.8: 头像图片安全处理工具。
 *
 * 问题背景：头像上传强依赖 javax.imageio.ImageIO(AWT)。在精简 JRE（缺少 java.desktop 模块）
 * 或极端环境下，ImageIO 会抛出 NoClassDefFoundError/ExceptionInInitializerError 等非 IOException，
 * 原代码只捕获 IOException，导致任何图片（含正常 PNG）上传都返回 500。
 *
 * 修复策略：
 * 1) 优先使用 ImageIO 将图片重编码为 PNG（剥离元数据/多态载荷，存储型 XSS 防护不变）；
 * 2) ImageIO 不可用或解析失败时，退回纯字节魔数校验——只接受真实的 PNG/JPEG/GIF/WebP 光栅图片，
 * SVG/HTML 等伪装内容因无光栅魔数被拒绝，XSS 防护依旧成立；
 * 3) 所有方法不抛异常，把失败信号以 null 返回，由调用方统一转成友好的 4xx/5xx。
 */
public final class ImageSafety {

    private ImageSafety() {
    }

    /** 头像最大 5MB（与 AuthService 校验一致）。 */
    public static final long MAX_AVATAR_BYTES = 5L * 1024 * 1024;

    /** 防解压炸弹：像素总量上限（约 4000 万像素）。 */
    public static final long MAX_AVATAR_PIXELS = 40_000_000L;

    /**
     * 通过魔数识别真实光栅图片格式，返回规范扩展名（png/jpeg/gif/webp/bmp）；非图片返回 null。
     * IronWall v1.45.0: 追加 BMP（"BM" 魔数）——白名单允许 .bmp 上传，内容体检必须能识别真 BMP。
     */
    public static String detectRasterFormat(byte[] bytes) {
        if (bytes == null || bytes.length < 12) {
            return null;
        }
        // PNG: 89 50 4E 47 0D 0A 1A 0A
        if ((bytes[0] & 0xFF) == 0x89 && bytes[1] == 'P' && bytes[2] == 'N' && bytes[3] == 'G'
                && bytes[4] == 0x0D && bytes[5] == 0x0A && bytes[6] == 0x1A && bytes[7] == 0x0A) {
            return "png";
        }
        // JPEG: FF D8 FF
        if ((bytes[0] & 0xFF) == 0xFF && (bytes[1] & 0xFF) == 0xD8 && (bytes[2] & 0xFF) == 0xFF) {
            return "jpeg";
        }
        // GIF87a / GIF89a
        if (bytes[0] == 'G' && bytes[1] == 'I' && bytes[2] == 'F' && bytes[3] == '8'
                && (bytes[4] == '7' || bytes[4] == '9') && bytes[5] == 'a') {
            return "gif";
        }
        // WebP: RIFF....WEBP
        if (bytes[0] == 'R' && bytes[1] == 'I' && bytes[2] == 'F' && bytes[3] == 'F'
                && bytes[8] == 'W' && bytes[9] == 'E' && bytes[10] == 'B' && bytes[11] == 'P') {
            return "webp";
        }
        // BMP: BM
        if (bytes[0] == 'B' && bytes[1] == 'M') {
            return "bmp";
        }
        return null;
    }

    /**
     * 用 ImageIO 将图片重编码为 PNG。任何环境/数据异常（含 AWT 缺失的 Error）都返回 null，
     * 由调用方退回魔数直存兜底。像素总量超限返回 null。
     */
    public static byte[] reencodeToPng(byte[] bytes) {
        if (bytes == null || bytes.length == 0 || bytes.length > MAX_AVATAR_BYTES) {
            return null;
        }
        try {
            java.awt.image.BufferedImage image =
                    javax.imageio.ImageIO.read(new java.io.ByteArrayInputStream(bytes));
            if (image == null) {
                return null;
            }
            long width = image.getWidth();
            long height = image.getHeight();
            if (width <= 0 || height <= 0 || width * height > MAX_AVATAR_PIXELS) {
                return null;
            }
            java.io.ByteArrayOutputStream baos =
                    new java.io.ByteArrayOutputStream(Math.max(1024, bytes.length / 2));
            if (!javax.imageio.ImageIO.write(image, "png", baos)) {
                return null;
            }
            byte[] out = baos.toByteArray();
            return out.length > 0 ? out : null;
        } catch (Throwable t) {
            return null;
        }
    }
}