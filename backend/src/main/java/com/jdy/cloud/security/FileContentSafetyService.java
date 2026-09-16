package com.jdy.cloud.security;

import com.jdy.cloud.util.ImageSafety;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.Enumeration;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/**
 * IronWall v1.28.4: 文件内容安全体检（上传链路强制体检）。
 *
 * 设计目标：
 * 1) 普通用户：后缀白名单之外再收紧——可执行程序/脚本类后缀一律拦截；
 * 内容上识别 PE/ELF/Mach-O 与 PHP/JSP/ASP/Shell/PowerShell 脚本，即使改名伪装也拦截；
 * 图片/视频/音频/压缩/办公文档必须与扩展名魔数匹配，防止"后缀正常、内容非正规"。
 * 2) 官方管理员：上传任意后缀、无视大小配额；但内容体检仍然强制——
 * 可执行/脚本内容伪装成其他后缀（改壳改名）一律拦截，且接入 ClamAV（若服务器已安装）做真实病毒扫描。
 * 3) 本服务只读文件头/尾与元数据，永不修改原文件；任何内部错误均 fail-open 放行，
 * 绝不把正常用户上传误杀在体检环节（检测不确定即放行，明确命中才拦截）。
 */
@Slf4j
@Service
public class FileContentSafetyService {

    /** IronWall v1.42.0: 加密存储文件的透明体检；无依赖时按明文读取（单测/降级场景）。 */
    @Autowired(required = false)
    private StorageCryptoService storageCrypto;

    /** 体检通过（共享单例，避免每文件新建对象）。 */
    public static final ScanResult SAFE = new ScanResult(true, null);

    /** IronWall v1.46.0: 普通用户禁止上传的可执行/脚本类后缀，统一由 UploadPolicy 提供（单一策略源）。 */
    public static final Set<String> NORMAL_USER_BLOCKED_EXTENSIONS = UploadPolicy.NORMAL_USER_BLOCKED_EXTENSIONS;

    /** 宏启用 Office 后缀族（内容含 vbaProject.bin 时仅这些后缀可承载）。 */
    private static final Set<String> MACRO_ENABLED_EXTENSIONS = Set.of(
            "docm", "xlsm", "pptm", "dotm", "xlam", "sldm"
    );

    /** 压缩包内一旦出现即拦截的危险条目后缀（普通用户）。 */
    private static final Set<String> DANGEROUS_ARCHIVE_ENTRY_EXTENSIONS = Set.of(
            "exe", "dll", "scr", "com", "sys", "msi", "msp", "pif", "cpl", "lnk", "drv", "ocx",
            "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "psm1", "hta",
            "reg", "inf", "scf", "sct", "chm", "msc", "wsc", "shs", "gadget",
            "jar", "apk", "iso", "img", "vhd", "vhdx", "efi", "swf", "class",
            "docm", "xlsm", "pptm", "dotm", "xlam", "sldm"
    );

    /** 勒索病毒加密产物双重后缀（Sorry 等家族追加 .sorry/.encrypted 等后缀）。 */
    private static final Pattern RANSOM_DOUBLE_EXT = Pattern.compile(
            "(?i)\\.(jpg|jpeg|png|gif|bmp|pdf|docx?|xlsx?|pptx?|txt|rtf|mp3|mp4|zip|rar|7z)"
            + "\\.(sorry|apologize|encrypted|crypted|locked|wncry|locky|zepto|odin|cerber|crypt|karma|nemty|maze|ryuk|conti)$");

    /** 赎金说明文件常见命名特征。 */
    private static final String[] RANSOM_NOTE_MARKERS = {
            "how_to_decrypt", "how to decrypt", "decrypt_instructions", "readme_restore",
            "!!!read_me", "!!read me", "restore_files", "your_files_are_encrypted", "recover_instructions"
    };

    /** 可执行程序类后缀族（管理员上传这些后缀时允许承载可执行内容）。 */
    private static final Set<String> EXECUTABLE_EXTENSIONS = Set.of(
            "exe", "dll", "scr", "com", "sys", "msi", "pif", "cpl",
            "jar", "apk", "ipa", "deb", "rpm", "crx", "xapk", "appimage", "rplib"
    );

    /** 脚本类后缀族（管理员上传这些后缀时允许承载脚本内容）。 */
    private static final Set<String> SCRIPT_EXTENSIONS = Set.of(
            "php", "phtml", "php3", "php4", "php5", "php7", "php8",
            "jsp", "jspx", "asp", "aspx", "ashx", "sh", "bash", "zsh",
            "ps1", "psm1", "vbs", "vbe", "js", "mjs", "cjs", "py", "pyw",
            "pl", "pm", "rb", "lua", "cgi", "wsf", "wsc", "bat", "cmd"
    );

    private static final Set<String> IMAGE_EXTENSIONS = Set.of(
            "jpg", "jpeg", "png", "gif", "webp", "bmp", "ico", "tif", "tiff"
    );

    private static final Set<String> VIDEO_EXTENSIONS = Set.of("mp4", "avi", "flv", "mkv", "mov", "webm", "wmv");

    private static final Set<String> AUDIO_EXTENSIONS = Set.of("mp3", "flac", "wav", "aac", "m4a", "ogg", "wma");

    private static final Set<String> ARCHIVE_EXTENSIONS = Set.of(
            "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "jar", "apk", "crx", "xapk", "deb", "rpm"
    );

    private static final Set<String> OFFICE_EXTENSIONS = Set.of(
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "epub", "mobi", "azw", "azw3"
    );

    /** 体检头部采样大小。 */
    private static final int HEAD_BYTES = 64 * 1024;

    /** ClamAV 可用性缓存：-1 未探测 / 0 不可用 / 1 clamdscan / 2 clamscan。 */
    private static volatile int clamAvMode = -1;

    public static final class ScanResult {
        private final boolean safe;
        private final String reason;
        private final String detected;

        ScanResult(boolean safe, String reason) {
            this(safe, reason, null);
        }

        ScanResult(boolean safe, String reason, String detected) {
            this.safe = safe;
            this.reason = reason;
            this.detected = detected;
        }

        public boolean safe() {
            return safe;
        }

        public String reason() {
            return reason;
        }

        public String detected() {
            return detected;
        }
    }

    /**
     * 对已落盘的物理文件做安全体检。
     *
     * @param file 已落盘物理文件
     * @param originalName 用户提交的原始文件名（用于后缀判定）
     * @param admin 是否官方管理员（管理员后缀不限，但内容伪装与病毒仍拦截）
     */
    public ScanResult scan(Path file, String originalName, boolean admin) {
        if (file == null || originalName == null || !Files.exists(file)) {
            return SAFE;
        }
        try {
            byte[] head = readHead(file);
            // IronWall v1.28.4: 上传体检 fail-closed——内容不可读时拒绝而不是放行，
            // 防杀软隔离/损坏文件/伪装 IO 错误绕过体检。
            if (head == null || head.length == 0) {
                return blocked("\u65e0\u6cd5\u8bfb\u53d6\u6587\u4ef6\u5185\u5bb9\u8fdb\u884c\u5b89\u5168\u4f53\u68c0\uff0c\u5df2\u62e6\u622a", "unreadable");
            }
            String ext = extensionOf(originalName);

            // 0) 勒索病毒文件名特征（双重后缀 / 赎金说明），对所有用户强制拦截
            String ransomName = detectRansomwareName(originalName);
            if (ransomName != null) {
                return blocked(ransomName, "ransomware-name");
            }

            // 1) 内容指纹识别：可执行程序 / 脚本（无视后缀，抓"改壳改名"）
            String detectedExe = detectExecutable(head);
            String detectedScript = detectScript(head);
            boolean isExecutable = detectedExe != null;
            boolean isScript = detectedScript != null;

            // 2) 病毒扫描（服务器安装 ClamAV 时生效；未安装自动跳过）
            String virus = clamAvScan(file);
            if (virus != null) {
                return blocked("文件包含病毒特征（" + virus + "），已由铁壁引擎拦截", virus);
            }

            // 2.1) 宏容器检测（vbaProject.bin）：普通用户一律拦截；管理员改壳伪装同样拦截
            boolean hasMacro = containsMacroContainer(file);
            if (hasMacro && !admin) {
                return blocked("检测到文档内含宏代码（宏病毒/钓鱼文档特征），普通用户禁止上传", "macro");
            }
            if (hasMacro && !MACRO_ENABLED_EXTENSIONS.contains(ext)) {
                return blocked("检测到宏代码伪装为 ." + ext + " 文档，已拦截", "macro");
            }

            // 2.2) IronWall v1.46.0: SVG 决策明确——允许纯矢量 SVG（云盘常见需求），
            // 含脚本/事件/外部引用/foreignObject 一律拦截（对管理员同样生效，防脚本伪装 .svg）。
            if ("svg".equals(ext)) {
                String svgIssue = detectUnsafeSvg(file);
                if (svgIssue != null) {
                    return blocked(svgIssue, svgIssue);
                }
            }

            // 3) 普通用户：可执行/脚本内容一律拦截；后缀与内容不匹配同样拦截
            if (!admin) {
                if (isExecutable) {
                    return blocked("检测到文件内容为可执行程序（" + detectedExe + "），普通用户禁止上传", detectedExe);
                }
                if (isScript) {
                    return blocked("检测到文件内容为脚本（" + detectedScript + "），普通用户禁止上传", detectedScript);
                }
                String mismatch = contentExtensionMismatch(head, ext);
                if (mismatch != null) {
                    return blocked("文件内容与扩展名不符（疑似伪装文件），已拦截", mismatch);
                }
                String zipIssue = scanZipEntries(file, ext);
                if (zipIssue != null) {
                    return blocked(zipIssue, "archive-danger");
                }
                return SAFE;
            }

            // 4) 管理员：后缀不限，但可执行/脚本内容若伪装成其他后缀仍拦截（防 Webshell/木马改壳）
            if (isExecutable && !EXECUTABLE_EXTENSIONS.contains(ext)) {
                return blocked("检测到可执行程序伪装为 ." + ext + " 文件（" + detectedExe + "），已拦截", detectedExe);
            }
            if (isScript && !SCRIPT_EXTENSIONS.contains(ext)) {
                return blocked("检测到脚本伪装为 ." + ext + " 文件（" + detectedScript + "），已拦截", detectedScript);
            }
            return SAFE;
        } catch (Exception e) {
            // fail-open：体检自身异常绝不误伤正常上传
            log.warn("[IronWall] file content scan failed, fail-open: {}", e.getMessage());
            return SAFE;
        }
    }

    private static ScanResult blocked(String reason, String detected) {
        log.warn("[IronWall] upload blocked by content safety: {} (detected={})", reason, detected);
        return new ScanResult(false, reason, detected);
    }

    private static String extensionOf(String name) {
        int dot = name.lastIndexOf('.');
        if (dot < 0 || dot == name.length() - 1) {
            return "";
        }
        return name.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    /** 勒索病毒文件名特征识别：双重后缀加密产物 / 赎金说明命名。 */
    static String detectRansomwareName(String name) {
        if (name == null || name.isBlank()) {
            return null;
        }
        String lower = name.toLowerCase(Locale.ROOT);
        if (RANSOM_DOUBLE_EXT.matcher(lower).find()) {
            return "检测到勒索病毒加密产物特征（文件被追加加密后缀），已拦截";
        }
        for (String marker : RANSOM_NOTE_MARKERS) {
            if (lower.contains(marker)) {
                return "检测到勒索病毒赎金说明文件特征，已拦截";
            }
        }
        return null;
    }

    /** 检测 Office 文档宏容器（vbaProject.bin），返回 true 表示含宏代码。 */
    boolean containsMacroContainer(Path file) {
        // IronWall v1.42.0: 加密文件用解密流枚举条目；明文文件保持 ZipFile 原语义
        if (storageCrypto != null && storageCrypto.isEncrypted(file)) {
            try (InputStream in = storageCrypto.openRead(file);
                 ZipInputStream zip = new ZipInputStream(in)) {
                int seen = 0;
                ZipEntry entry;
                while ((entry = zip.getNextEntry()) != null) {
                    if (++seen > 256) {
                        return false;
                    }
                    if (entry.getName().toLowerCase(Locale.ROOT).endsWith("vbaproject.bin")) {
                        return true;
                    }
                }
            } catch (Exception e) {
                // 非 zip / 损坏 / 加密压缩包不视为宏容器
            }
            return false;
        }
        try (ZipFile zip = new ZipFile(file.toFile())) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            int seen = 0;
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (++seen > 256) {
                    return false;
                }
                if (entry.getName().toLowerCase(Locale.ROOT).endsWith("vbaproject.bin")) {
                    return true;
                }
            }
        } catch (Exception e) {
            // 非 zip / 损坏 / 加密压缩包不视为宏容器
        }
        return false;
    }

    /** 普通用户压缩包投毒检测：危险条目 + 压缩炸弹防护。 */
    String scanZipEntries(Path file, String ext) {
        if (!"zip".equals(ext)) {
            return null;
        }
        // IronWall v1.42.0: 加密文件用解密流枚举条目（流式 size 未知，条目数上限仍生效）
        if (storageCrypto != null && storageCrypto.isEncrypted(file)) {
            try (InputStream in = storageCrypto.openRead(file);
                 ZipInputStream zip = new ZipInputStream(in)) {
                int count = 0;
                ZipEntry entry;
                while ((entry = zip.getNextEntry()) != null) {
                    count++;
                    if (count > 2000) {
                        return "压缩包条目过多（疑似压缩炸弹），已拦截";
                    }
                    if (entry.isDirectory()) {
                        continue;
                    }
                    String name = entry.getName().toLowerCase(Locale.ROOT);
                    int dot = name.lastIndexOf('.');
                    if (dot > 0 && DANGEROUS_ARCHIVE_ENTRY_EXTENSIONS.contains(name.substring(dot + 1))) {
                        return "压缩包内包含可执行/脚本/宏文件（." + name.substring(dot + 1) + "），已拦截";
                    }
                }
            } catch (Exception e) {
                // 损坏/加密压缩包不误伤
            }
            return null;
        }
        try (ZipFile zip = new ZipFile(file.toFile())) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            int count = 0;
            long total = 0;
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                count++;
                total += entry.getSize();
                if (count > 2000) {
                    return "压缩包条目过多（疑似压缩炸弹），已拦截";
                }
                if (total > 2L * 1024 * 1024 * 1024) {
                    return "压缩包解压体积超限（疑似压缩炸弹），已拦截";
                }
                if (entry.isDirectory()) {
                    continue;
                }
                String name = entry.getName().toLowerCase(Locale.ROOT);
                int dot = name.lastIndexOf('.');
                if (dot > 0 && DANGEROUS_ARCHIVE_ENTRY_EXTENSIONS.contains(name.substring(dot + 1))) {
                    return "压缩包内包含可执行/脚本/宏文件（." + name.substring(dot + 1) + "），已拦截";
                }
            }
        } catch (Exception e) {
            // 损坏/加密压缩包不误伤
        }
        return null;
    }

    private byte[] readHead(Path file) {
        try (InputStream in = storageCrypto != null ? storageCrypto.openRead(file) : Files.newInputStream(file)) {
            byte[] buf = new byte[HEAD_BYTES];
            int n = 0;
            while (n < buf.length) {
                int r = in.read(buf, n, buf.length - n);
                if (r < 0) {
                    break;
                }
                n += r;
            }
            return n == 0 ? null : Arrays.copyOf(buf, n);
        } catch (IOException e) {
            return null;
        }
    }

    // ==================== 可执行程序识别 ====================

    static String detectExecutable(byte[] b) {
        if (b.length >= 2 && (b[0] & 0xFF) == 0x4D && (b[1] & 0xFF) == 0x5A) {
            return "Windows PE (MZ)";
        }
        if (b.length >= 4 && (b[0] & 0xFF) == 0x7F && b[1] == 'E' && b[2] == 'L' && b[3] == 'F') {
            return "Linux ELF";
        }
        if (b.length >= 4) {
            long magic = ((long) (b[0] & 0xFF) << 24) | ((long) (b[1] & 0xFF) << 16)
                    | ((long) (b[2] & 0xFF) << 8) | (b[3] & 0xFF);
            if (magic == 0xFEEDFACEL || magic == 0xCEFAEDFEL || magic == 0xFEEDFACFL || magic == 0xCFFAEDFEL
                    || magic == 0xCAFEBABEL || magic == 0xBEBAFECAL) {
                return "Mach-O";
            }
        }
        // IronWall v1.28.8: 勒索/钓鱼常见投递载体识别
        if (b.length >= 16 && (b[0] & 0xFF) == 0x4C && b[1] == 0 && b[2] == 0 && b[3] == 0
                && (b[4] & 0xFF) == 0x01 && (b[5] & 0xFF) == 0x14 && (b[6] & 0xFF) == 0x02 && b[7] == 0
                && (b[8] & 0xFF) == 0xC0 && b[9] == 0 && b[10] == 0 && b[11] == 0
                && b[12] == 0 && b[13] == 0 && b[14] == 0 && (b[15] & 0xFF) == 0x46) {
            return "Windows 快捷方式 (LNK)";
        }
        if (startsWith(b, "AU3!")) {
            return "AutoIt 编译可执行文件";
        }
        if (b.length >= 8 && (b[0] & 0xFF) == 0x4D && (b[1] & 0xFF) == 0x45 && (b[2] & 0xFF) == 0x49
                && (b[3] & 0xFF) == 0x0C && (b[4] & 0xFF) == 0x0B && (b[5] & 0xFF) == 0x0A
                && (b[6] & 0xFF) == 0x0B && (b[7] & 0xFF) == 0x0E) {
            return "PyInstaller 打包可执行文件";
        }
        if (containsAscii(b, 0, 4096, "NullsoftInst")) {
            return "NSIS 安装程序";
        }
        if (containsAscii(b, 0, 4096, "Inno Setup")) {
            return "Inno Setup 安装程序";
        }
        if (startsWithIgnoreCase(b, "MSCF")) {
            return "Windows 安装包 (MSCF)";
        }
        if (startsWithIgnoreCase(b, "@echo off") || startsWithIgnoreCase(b, "@echo on")) {
            return "批处理脚本 (BAT)";
        }
        return null;
    }

    // ==================== 脚本识别 ====================

    static String detectScript(byte[] b) {
        byte[] t = skipBomAndWhitespace(b, 256);
        if (t.length < 2) {
            return null;
        }
        if (startsWithIgnoreCase(t, "<?php") || startsWith(t, "<?=")) {
            return "PHP 脚本";
        }
        if (startsWith(t, "<?") && t.length > 2 && Character.isWhitespace((char) (t[2] & 0xFF))) {
            return "PHP 脚本";
        }
        if (startsWith(t, "<%@")) {
            return "JSP 脚本";
        }
        if (startsWith(t, "<%")) {
            return "ASP/JSP 脚本";
        }
        if (startsWith(t, "#!")) {
            return "Shell 脚本";
        }
        if (startsWithIgnoreCase(t, "#requires")) {
            return "PowerShell 脚本";
        }
        if (startsWithIgnoreCase(t, "<script")) {
            return "网页脚本";
        }
        return null;
    }

    // ==================== SVG 净化校验（IronWall v1.46.0） ====================

    private static final java.util.regex.Pattern SVG_UNSAFE_PATTERN = java.util.regex.Pattern.compile(
            "(?is)(<\\s*script|on\\w+\\s*=|javascript\\s*:|"
            + "<\\s*(foreignObject|iframe|object|embed)\\b|"
            + "<!\\s*(DOCTYPE|ENTITY|ELEMENT|ATTLIST)\\b|"
            + "xlink:href\\s*=\\s*[\"']?\\s*https?://|"
            + "\\bhref\\s*=\\s*[\"']?\\s*https?://|"
            + "\\bsrc\\s*=\\s*[\"']?\\s*https?://|"
            + "<\\?xml-stylesheet|data\\s*:\\s*text/html)");

    /** SVG 全文上限：低于该值全量扫描，高于取首尾各 64KB（防超大矢量撑爆内存）。 */
    private static final int SVG_FULL_SCAN_BYTES = 1024 * 1024;

    /** 返回命中描述，null 表示纯矢量 SVG 放行。 */
    public String detectUnsafeSvg(Path file) {
        try {
            long size = Files.size(file);
            byte[] sample;
            boolean fullScan = false;
            try (InputStream in = storageCrypto != null ? storageCrypto.openRead(file) : Files.newInputStream(file)) {
                if (size <= SVG_FULL_SCAN_BYTES) {
                    sample = in.readAllBytes();
                    fullScan = true;
                } else {
                    byte[] head = in.readNBytes(HEAD_BYTES);
                    // 尾部采样：跳过中段，防止脚本塞在文件末尾
                    long skip = Math.max(0L, size - 2L * HEAD_BYTES);
                    in.skipNBytes(skip);
                    byte[] tail = in.readNBytes(2 * HEAD_BYTES);
                    sample = new byte[head.length + tail.length];
                    System.arraycopy(head, 0, sample, 0, head.length);
                    System.arraycopy(tail, 0, sample, head.length, tail.length);
                }
            }
            String textIssue = detectUnsafeSvgText(new String(sample, StandardCharsets.UTF_8));
            if (textIssue != null) {
                return textIssue;
            }
            // IronWall v1.47.9: 完整 SVG（<=1MB）再走 XML 解析级白名单，正则盲区第二道闸
            return fullScan ? validateSvgXml(sample) : null;
        } catch (IOException e) {
            // 读取失败走 fail-closed 的不可读拦截（调用方已保证 head 可读）
            return "SVG 内容无法读取，已拦截";
        }
    }

    /** 文件头网页脚本标记（任意位置）：与 历史 multipart 契约一致，命中即返回描述。 */
    private static final java.util.regex.Pattern FILE_HEAD_SCRIPT_PATTERN = java.util.regex.Pattern.compile(
            "(?is)(<\\s*script\\b|</\\s*script|<\\?php|<\\?=|<%@|<%\\s*[@=-]|<%\\s+|"
            + "(^|\\n)\\s*#!|(^|\\n)\\s*#requires|(^|\\n)\\s*@echo)");

    /** 供 MultipartBodyScanner 复用（同一规则源）：返回命中描述，null 表示放行。 */
    static String detectFileHeadScript(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        java.util.regex.Matcher m = FILE_HEAD_SCRIPT_PATTERN.matcher(text);
        if (m.find()) {
            String hit = m.group().toLowerCase(java.util.Locale.ROOT);
            if (hit.contains("script")) {
                return "文件内容包含网页脚本标记（<script>）";
            }
            return "文件内容包含脚本标记（" + hit.trim() + "）";
        }
        return null;
    }

    /** 文本视图校验：供 multipart 文件头扫描复用（同一规则源）。 */
    static String detectUnsafeSvgText(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        java.util.regex.Matcher m = SVG_UNSAFE_PATTERN.matcher(text);
        if (m.find()) {
            String hit = m.group().toLowerCase(java.util.Locale.ROOT);
            // javascript: 优先于泛化 script 关键字，保证审计提示精确（诊断细化）
            if (hit.contains("javascript:")) {
                return "SVG 内嵌 javascript: 协议被拦截";
            }
            if (hit.contains("doctype") || hit.contains("entity")
                    || hit.contains("element") || hit.contains("attlist")) {
                return "SVG 内嵌实体声明/DTD 被拦截";
            }
            if (hit.contains("script") || hit.contains("<?xml-stylesheet")) {
                return "SVG 内嵌网页脚本被拦截（<script>/样式表）";
            }
            if (hit.startsWith("on") && hit.contains("=")) {
                return "SVG 内嵌事件处理器（" + hit.substring(0, Math.min(12, hit.length())) + "…）被拦截";
            }
            if (hit.contains("foreignobject") || hit.contains("iframe") || hit.contains("<object") || hit.contains("<embed")) {
                return "SVG 内嵌外部对象（foreignObject/iframe/object/embed）被拦截";
            }
            if (hit.contains("http")) {
                return "SVG 外部资源引用被拦截";
            }
            return "SVG 包含不安全结构，已拦截";
        }
        return null;
    }

    /** IronWall v1.47.9: 解析级禁入元素（与正则层同一决策，双保险）。 */
    private static final java.util.Set<String> SVG_FORBIDDEN_ELEMENTS = java.util.Set.of(
            "script", "foreignobject", "iframe", "object", "embed");

    /**
     * IronWall v1.47.9: 完整 SVG 的 XML 解析级白名单。
     * 禁 doctype / 外部实体 / 外部 DTD / 脚本类元素 / on* 事件属性 / javascript: 协议；
     * 解析失败（含畸形 XML、实体展开）一律拒绝（fail-closed）。
     */
    private String validateSvgXml(byte[] full) {
        try {
            javax.xml.parsers.DocumentBuilderFactory factory =
                    javax.xml.parsers.DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            factory.setNamespaceAware(true);
            javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
            org.w3c.dom.Document doc = builder.parse(new java.io.ByteArrayInputStream(full));
            org.w3c.dom.Element root = doc.getDocumentElement();
            if (root == null || !"svg".equalsIgnoreCase(root.getLocalName())) {
                return "SVG 根元素不合法，已拦截";
            }
            return scanSvgElement(root, 0);
        } catch (Exception e) {
            return "SVG 解析失败或包含不安全结构，已拦截";
        }
    }

    /** IronWall v1.47.9: 深度优先扫描元素与属性；嵌套深度封顶防解析炸弹。 */
    private String scanSvgElement(org.w3c.dom.Element element, int depth) {
        if (depth > 24) {
            return "SVG 嵌套过深，已拦截";
        }
        String name = element.getLocalName() == null ? element.getTagName() : element.getLocalName();
        if (SVG_FORBIDDEN_ELEMENTS.contains(name.toLowerCase(java.util.Locale.ROOT))) {
            return "SVG 内嵌不安全元素（" + name + "）被拦截";
        }
        org.w3c.dom.NamedNodeMap attrs = element.getAttributes();
        for (int i = 0; i < attrs.getLength(); i++) {
            org.w3c.dom.Node node = attrs.item(i);
            String attrName = node.getNodeName() == null ? "" : node.getNodeName().toLowerCase(java.util.Locale.ROOT);
            if (attrName.startsWith("on")) {
                return "SVG 内嵌事件处理器（" + attrName + "）被拦截";
            }
            String value = node.getNodeValue();
            if (value != null && value.toLowerCase(java.util.Locale.ROOT).contains("javascript:")) {
                return "SVG 内嵌 javascript: 协议被拦截";
            }
        }
        org.w3c.dom.NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            org.w3c.dom.Node child = children.item(i);
            if (child.getNodeType() == org.w3c.dom.Node.ELEMENT_NODE) {
                String issue = scanSvgElement((org.w3c.dom.Element) child, depth + 1);
                if (issue != null) {
                    return issue;
                }
            }
        }
        return null;
    }

    // ==================== 后缀-内容匹配 ====================

    /**
     * 普通用户：常见伪装类型必须"表里如一"。返回不匹配描述，null 表示通过。
     */
    static String contentExtensionMismatch(byte[] b, String ext) {
        if (ext.isEmpty()) {
            return null;
        }
        // IronWall v1.46.0: svg 是 XML 文本而非光栅图，不做魔数匹配，由 detectUnsafeSvg 负责。
        if ("svg".equals(ext)) {
            return null;
        }
        if (IMAGE_EXTENSIONS.contains(ext)) {
            String raster = ImageSafety.detectRasterFormat(b);
            if (raster == null) {
                return "图片内容与 ." + ext + " 不符";
            }
            return null;
        }
        if (VIDEO_EXTENSIONS.contains(ext)) {
            if (isMp4Like(b)) {
                return null;
            }
            if (ext.equals("avi") || ext.equals("wmv")) {
                if (b.length >= 12 && asciiAt(b, 0, "RIFF") && asciiAt(b, 8, "AVI ")) {
                    return null;
                }
            }
            if (ext.equals("flv") && asciiAt(b, 0, "FLV")) {
                return null;
            }
            if ((ext.equals("mkv") || ext.equals("webm")) && b.length >= 4
                    && (b[0] & 0xFF) == 0x1A && (b[1] & 0xFF) == 0x45 && (b[2] & 0xFF) == 0xDF && (b[3] & 0xFF) == 0xA3) {
                return null;
            }
            if (ext.equals("mov") && containsAscii(b, 0, 16, "ftyp")) {
                return null;
            }
            return "视频内容与 ." + ext + " 不符";
        }
        if (AUDIO_EXTENSIONS.contains(ext)) {
            if (ext.equals("mp3") && (asciiAt(b, 0, "ID3") || isMpegFrame(b))) {
                return null;
            }
            if (ext.equals("flac") && asciiAt(b, 0, "fLaC")) {
                return null;
            }
            if (ext.equals("wav") && b.length >= 12 && asciiAt(b, 0, "RIFF") && asciiAt(b, 8, "WAVE")) {
                return null;
            }
            if ((ext.equals("aac") || ext.equals("m4a")) && (isAdtsFrame(b) || containsAscii(b, 0, 16, "ftyp"))) {
                return null;
            }
            if (ext.equals("ogg") && asciiAt(b, 0, "OggS")) {
                return null;
            }
            if (ext.equals("wma") && b.length >= 16 && containsAscii(b, 0, 64, "asf")) {
                return null;
            }
            return "音频内容与 ." + ext + " 不符";
        }
        if (ARCHIVE_EXTENSIONS.contains(ext)) {
            if (asciiAt(b, 0, "PK")) {
                return null; // zip/jar/apk/crx/xapk/deb/rpm(部分)
            }
            if (ext.equals("rar") && asciiAt(b, 0, "Rar!")) {
                return null;
            }
            if (ext.equals("7z") && b.length >= 6 && (b[0] & 0xFF) == 0x37 && (b[1] & 0xFF) == 0x7A
                    && (b[2] & 0xFF) == 0xBC && (b[3] & 0xFF) == 0xAF && (b[4] & 0xFF) == 0x27 && (b[5] & 0xFF) == 0x1C) {
                return null;
            }
            if (ext.equals("gz") && b.length >= 2 && (b[0] & 0xFF) == 0x1F && (b[1] & 0xFF) == 0x8B) {
                return null;
            }
            if (ext.equals("bz2") && asciiAt(b, 0, "BZh")) {
                return null;
            }
            if (ext.equals("xz") && b.length >= 6 && (b[0] & 0xFF) == 0xFD && asciiAt(b, 1, "7zXZ")) {
                return null;
            }
            if (ext.equals("tar") && b.length >= 262 && asciiAt(b, 257, "ustar")) {
                return null;
            }
            return "压缩包内容与 ." + ext + " 不符";
        }
        if (OFFICE_EXTENSIONS.contains(ext)) {
            if (ext.equals("pdf") && containsAscii(b, 0, 1024, "%PDF")) {
                return null;
            }
            if (ext.equals("doc") && b.length >= 8 && (b[0] & 0xFF) == 0xD0 && (b[1] & 0xFF) == 0xCF
                    && (b[2] & 0xFF) == 0x11 && (b[3] & 0xFF) == 0xE0) {
                return null;
            }
            if ((ext.equals("docx") || ext.equals("xlsx") || ext.equals("pptx") || ext.equals("epub"))
                    && asciiAt(b, 0, "PK")) {
                return null;
            }
            if ((ext.equals("mobi") || ext.equals("azw") || ext.equals("azw3"))
                    && (containsAscii(b, 0, 128, "BOOKMOBI") || asciiAt(b, 0, "PK"))) {
                return null;
            }
            if (ext.equals("xls") && (b.length >= 8 && (b[0] & 0xFF) == 0xD0 && (b[1] & 0xFF) == 0xCF
                    && (b[2] & 0xFF) == 0x11 && (b[3] & 0xFF) == 0xE0)) {
                return null;
            }
            if (ext.equals("ppt") && b.length >= 8 && (b[0] & 0xFF) == 0xD0 && (b[1] & 0xFF) == 0xCF
                    && (b[2] & 0xFF) == 0x11 && (b[3] & 0xFF) == 0xE0) {
                return null;
            }
            return "文档内容与 ." + ext + " 不符";
        }
        return null;
    }

    // ==================== ClamAV（可选，服务器安装后自动生效） ====================

    private String clamAvScan(Path file) {
        int mode = clamAvMode;
        if (mode == -1) {
            mode = probeClamAv();
            clamAvMode = mode;
        }
        if (mode == 0) {
            return null;
        }
        String binary = mode == 1 ? "clamdscan" : "clamscan";
        Path scanTarget = file;
        Path plainTemp = null;
        // IronWall v1.42.0: 加密文件先解密到临时明文再交病毒引擎，扫描后即删
        if (storageCrypto != null && storageCrypto.isEncrypted(file)) {
            try {
                plainTemp = Files.createTempFile("iw-clamav-", ".scan");
                try (InputStream in = storageCrypto.openRead(file);
                     java.io.OutputStream out = Files.newOutputStream(plainTemp)) {
                    in.transferTo(out);
                }
                scanTarget = plainTemp;
            } catch (Exception e) {
                log.warn("[IronWall] clamav decrypt temp failed, skip: {}", e.getMessage());
                if (plainTemp != null) {
                    try { Files.deleteIfExists(plainTemp); } catch (Exception ignored) { }
                }
                return null;
            }
        }
        try {
            ProcessBuilder pb = new ProcessBuilder(binary, "--no-summary", scanTarget.toAbsolutePath().toString());
            pb.redirectErrorStream(true);
            Process process = pb.start();
            StringBuilder out = new StringBuilder();
            try (InputStream in = process.getInputStream()) {
                byte[] buf = new byte[4096];
                int n;
                while ((n = in.read(buf)) > 0) {
                    out.append(new String(buf, 0, n, java.nio.charset.StandardCharsets.UTF_8));
                    if (out.length() > 8192) {
                        break;
                    }
                }
            }
            if (!process.waitFor(90, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                log.warn("[IronWall] clamav scan timeout, skip");
                return null;
            }
            int code = process.exitValue();
            if (code == 1) {
                return sanitizeVirusName(out.toString());
            }
            if (code != 0) {
                log.debug("[IronWall] clamav unavailable this run (code={}), skip: {}", code, out);
            }
            return null;
        } catch (Exception e) {
            log.warn("[IronWall] clamav scan failed, skip: {}", e.getMessage());
            return null;
        } finally {
            if (plainTemp != null) {
                try { Files.deleteIfExists(plainTemp); } catch (Exception ignored) { }
            }
        }
    }

    private static int probeClamAv() {
        for (String[] pair : new String[][]{{"clamdscan", "1"}, {"clamscan", "2"}}) {
            try {
                Process process = new ProcessBuilder(pair[0], "--version").redirectErrorStream(true).start();
                if (process.waitFor(10, TimeUnit.SECONDS)) {
                    return Integer.parseInt(pair[1]);
                }
                process.destroyForcibly();
            } catch (Exception ignored) {
                // 未安装，继续探测下一种
            }
        }
        return 0;
    }

    private static String sanitizeVirusName(String raw) {
        if (raw == null || raw.isBlank()) {
            return "未知威胁";
        }
        String trimmed = raw.trim();
        int idx = trimmed.lastIndexOf(':');
        if (idx >= 0 && idx < trimmed.length() - 1) {
            trimmed = trimmed.substring(idx + 1).trim();
        }
        int cut = trimmed.indexOf("FOUND");
        if (cut >= 0) {
            trimmed = trimmed.substring(0, cut).trim();
        }
        return trimmed.length() > 80 ? trimmed.substring(0, 80) : trimmed;
    }

    // ==================== 字节工具 ====================

    private static byte[] skipBomAndWhitespace(byte[] b, int max) {
        int i = 0;
        if (b.length >= 3 && (b[0] & 0xFF) == 0xEF && (b[1] & 0xFF) == 0xBB && (b[2] & 0xFF) == 0xBF) {
            i = 3;
        }
        int limit = Math.min(b.length, i + max);
        while (i < limit && Character.isWhitespace((char) (b[i] & 0xFF))) {
            i++;
        }
        if (i >= b.length) {
            return new byte[0];
        }
        return Arrays.copyOfRange(b, i, b.length);
    }

    private static boolean startsWith(byte[] b, String prefix) {
        return b.length >= prefix.length() && asciiAt(b, 0, prefix);
    }

    private static boolean startsWithIgnoreCase(byte[] b, String prefix) {
        if (b.length < prefix.length()) {
            return false;
        }
        for (int i = 0; i < prefix.length(); i++) {
            char a = (char) (b[i] & 0xFF);
            char c = prefix.charAt(i);
            if (a != c && a != (c >= 'a' && c <= 'z' ? c - 32 : (c >= 'A' && c <= 'Z' ? c + 32 : c))) {
                return false;
            }
        }
        return true;
    }

    private static boolean asciiAt(byte[] b, int offset, String prefix) {
        if (b.length < offset + prefix.length()) {
            return false;
        }
        for (int i = 0; i < prefix.length(); i++) {
            if ((char) (b[offset + i] & 0xFF) != prefix.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    private static boolean containsAscii(byte[] b, int from, int to, String needle) {
        int end = Math.min(b.length - needle.length(), to);
        for (int i = Math.max(0, from); i <= end; i++) {
            if (asciiAt(b, i, needle)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isMp4Like(byte[] b) {
        return containsAscii(b, 0, 16, "ftyp") || containsAscii(b, 0, 64, "moov") || containsAscii(b, 0, 64, "mdat");
    }

    private static boolean isMpegFrame(byte[] b) {
        return b.length >= 2 && (b[0] & 0xFF) == 0xFF && ((b[1] & 0xE0) == 0xE0 || (b[1] & 0xE0) == 0xC0);
    }

    private static boolean isAdtsFrame(byte[] b) {
        return b.length >= 2 && (b[0] & 0xFF) == 0xFF && (b[1] & 0xF0) == 0xF0;
    }
}
