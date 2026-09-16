package com.jdy.cloud.security;

import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.ErrorCode;
import com.jdy.cloud.util.SecurityUtils;

import java.util.Set;

/**
 * IronWall v1.46.0: 上传策略单一数据源。
 * check / upload（直传）/ merge 三处共用本类名单与阈值，杜绝多套判定漂移；
 * 版本号 POLICY_VERSION 随策略变更递增，通过 site/info 与 check 响应下发。
 */
public final class UploadPolicy {

    /** 策略版本：名单/阈值任一变更时必须递增。 */
    public static final String POLICY_VERSION = "v1.47.0";

    /** 直传（multipart /files/upload）单文件上限：普通用户 10MB，超出必须走分片（管理员豁免）。 */
    public static final long DIRECT_UPLOAD_MAX_BYTES = 10L * 1024 * 1024;
    /** 分片大小（与前端分片对齐）。 */
    public static final long CHUNK_SIZE_BYTES = 10L * 1024 * 1024;
    /** 普通用户单文件总量上限。 */
    public static final long MAX_FILE_BYTES = 850L * 1024 * 1024;
    /** 管理员单文件安全阀。 */
    public static final long ADMIN_MAX_FILE_BYTES = 20L * 1024 * 1024 * 1024;

    /**
     * IronWall v1.47.0: 普通用户允许的扩展名——产品口径精确四类 27 个。
     * 任何名单变更必须同步递增 POLICY_VERSION，并在 UploadPolicyTest 的精确集合断言中固化。
     */
    public static final Set<String> NORMAL_USER_ALLOWED_EXTENSIONS = Set.of(
            // 文档类（10）
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "md", "csv",
            // 图片类（7，svg 允许但需通过内容净化校验）
            "jpg", "jpeg", "png", "gif", "bmp", "webp", "svg",
            // 音视频类（7）
            "mp3", "wav", "flac", "mp4", "mov", "mkv", "avi",
            // 压缩包类（3）
            "zip", "7z", "rar"
    );

    /** 普通用户禁止上传的可执行/脚本类后缀（原 FileContentSafetyService.NORMAL_USER_BLOCKED_EXTENSIONS）。 */
    public static final Set<String> NORMAL_USER_BLOCKED_EXTENSIONS = Set.of(
            "exe", "dll", "scr", "com", "sys", "msi", "pif", "cpl", "lnk",
            "bat", "cmd", "jar", "apk", "ipa", "deb", "rpm", "crx", "xapk", "appimage", "rplib",
            "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "psm1", "hta",
            "reg", "inf", "scf", "sct", "msp", "mst", "ocx", "drv",
            "chm", "msc", "wsc", "iso", "img", "vhd", "vhdx", "efi", "shs", "gadget", "swf", "dmg",
            "docm", "xlsm", "pptm", "dotm", "xlam", "sldm"
    );

    /** 文件名任一扩展段命中即拒绝的危险后缀（防 .html.txt / .php.jpg 双扩展走私；仅约束普通用户）。 */
    public static final Set<String> DANGEROUS_EXTENSION_SEGMENTS = Set.of(
            "html", "htm", "shtml", "xhtml", "php", "phtml", "php3", "php4", "php5", "php7", "php8",
            "jsp", "jspx", "asp", "aspx", "ashx", "js", "mjs", "cjs", "vbs", "vbe", "sh", "bash", "zsh",
            "bat", "cmd", "ps1", "psm1", "hta", "wsf", "wsh", "py", "pyw", "pl", "pm", "rb", "cgi"
    );

    private UploadPolicy() {
    }

    /** check/upload/merge 统一入口：文件名策略。admin 只校验文件名合法性，不限后缀（产品需求：管理员无限制上传）。 */
    public static void validateFilename(String filename, boolean admin) {
        if (!SecurityUtils.isValidFilename(filename)) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "invalid filename");
        }
        String ext = extensionOf(filename);
        if (ext.isEmpty()) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "文件必须有扩展名");
        }
        if (!admin && NORMAL_USER_BLOCKED_EXTENSIONS.contains(ext)) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "出于安全考虑，普通用户不能上传可执行或脚本文件: ." + ext);
        }
        if (!admin && !NORMAL_USER_ALLOWED_EXTENSIONS.contains(ext)) {
            throw new BusinessException(ErrorCode.FILE_TYPE_NOT_ALLOWED.getCode(), "不支持的文件类型: ." + ext);
        }
        String dangerous = dangerousSegmentOf(filename);
        if (!admin && dangerous != null) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(),
                    "出于安全考虑，禁止通过多重扩展名伪装文件类型（含 ." + dangerous + " 段）");
        }
    }

    /** check/upload/merge 统一入口：尺寸策略。direct=true 时普通用户受直传上限约束。 */
    public static void validateSize(long size, boolean admin, boolean direct) {
        if (size <= 0) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(), "文件不能为空");
        }
        long limit = admin ? ADMIN_MAX_FILE_BYTES : MAX_FILE_BYTES;
        if (size > limit) {
            throw new BusinessException(ErrorCode.FILE_TOO_LARGE);
        }
        if (direct && !admin && size > DIRECT_UPLOAD_MAX_BYTES) {
            throw new BusinessException(ErrorCode.BAD_REQUEST.getCode(),
                    "文件超过直传上限（" + (DIRECT_UPLOAD_MAX_BYTES / 1024 / 1024) + "MB），请使用分片上传");
        }
    }

    public static String extensionOf(String filename) {
        if (filename != null && filename.contains(".")) {
            return filename.substring(filename.lastIndexOf(".") + 1).toLowerCase(java.util.Locale.ROOT);
        }
        return "";
    }

    private static String dangerousSegmentOf(String filename) {
        if (filename == null) {
            return null;
        }
        String lower = filename.toLowerCase(java.util.Locale.ROOT);
        int start = 0;
        while (true) {
            int dot = lower.indexOf('.', start);
            if (dot < 0) {
                break;
            }
            int end = lower.indexOf('.', dot + 1);
            String seg = end < 0 ? lower.substring(dot + 1) : lower.substring(dot + 1, end);
            if (DANGEROUS_EXTENSION_SEGMENTS.contains(seg)) {
                return seg;
            }
            start = dot + 1;
        }
        return null;
    }
}