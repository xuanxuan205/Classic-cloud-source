package com.jdy.cloud.util;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * IronWall v1.9: 头像存储目录解析与自愈兜底。
 *
 * 背景：服务器上头像上传持续 500 的根因是部署 CWD/权限导致 ./uploads/avatars 无法写入，
 * 且旧头像因路径漂移返回 404。本工具提供：
 * 1) 主目录：UPLOAD_DIR / app.storage.upload-dir 配置的绝对化路径；
 * 2) 兜底目录：java.io.tmpdir/classic-cloud/avatars —— 主目录不可写时保证头像功能可用；
 * 3) 上传与读取共用同一候选列表，先主后备，读写永远落在同一位置。
 */
public final class StoragePaths {

    private StoragePaths() {
    }

    /** uploadDir 空值兜底 + 规范化（供文件上传等其它模块复用语义）。 */
    public static String resolveBaseDir(String configured) {
        if (configured == null || configured.isBlank()) {
            return "./uploads";
        }
        return configured.trim();
    }

    /**
     * 返回头像目录候选列表：先主目录，后兜底目录。
     * 任何路径构造异常都跳过该候选，保证不抛异常。
     */
    public static List<Path> avatarDirs(String configured) {
        List<Path> dirs = new ArrayList<>();
        String base = resolveBaseDir(configured);
        try {
            Path primary = Path.of(base).toAbsolutePath().normalize().resolve("avatars").normalize();
            dirs.add(primary);
        } catch (Exception ignored) {
            // 配置了非法路径时跳过，交给兜底目录
        }
        try {
            Path fallback = Path.of(System.getProperty("java.io.tmpdir"), "classic-cloud", "avatars")
                    .toAbsolutePath().normalize();
            if (!dirs.contains(fallback)) {
                dirs.add(fallback);
            }
        } catch (Exception ignored) {
            // tmpdir 异常时保持已有候选
        }
        return dirs;
    }
}