package com.jdy.cloud.util;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public final class SecurityUtils {

    private static final Pattern XSS_PATTERN = Pattern.compile(
            "(?i)<script|</script|<iframe|javascript:|on\\w+\\s*=|expression\\s*\\(|eval\\s*\\(|data\\s*:",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_\\u4e00-\\u9fa5]{3,20}$");
    private static final Pattern SAFE_USERNAME_PATTERN = Pattern.compile("^[\\p{L}\\p{N}_\\-. ]{2,30}$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
    private static final Pattern FILENAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_\\-\\u4e00-\\u9fa5.() ]+$");

    // IronWall v1.21.2 F-01: 保留名黑名单，防止改名/注册冒充官方身份（admin/root/系统 等）
    private static final Set<String> RESERVED_USERNAMES = Set.of(
            "admin", "administrator", "root", "system", "sysadmin", "support",
            "moderator", "owner", "official", "service", "bot", "staff", "superuser",
            "管理员", "管理", "系统", "官方", "客服", "机器人");

    private SecurityUtils() {}

    public static boolean containsXss(String input) {
        if (input == null) return false;
        return XSS_PATTERN.matcher(input).find();
    }

    public static String sanitizeHtml(String input) {
        if (input == null) return null;
        return input
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;");
    }

    public static boolean isValidUsername(String username) {
        return username != null && USERNAME_PATTERN.matcher(username).matches();
    }

    // IronWall v1.3: 用户名白名单（2-30位，允许中英文/数字/下划线/短横线/点号/空格，拒绝HTML与脚本字符）
    public static boolean isReservedUsername(String username) {
        if (username == null) return false;
        return RESERVED_USERNAMES.contains(username.trim().toLowerCase(Locale.ROOT));
    }

    public static boolean isSafeUsername(String username) {
        if (username == null) return false;
        return SAFE_USERNAME_PATTERN.matcher(username).matches() && !containsXss(username);
    }

    // IronWall v1.3: 文本字段剥离HTML标签与控制字符（分享描述/公告等）
    public static String stripHtmlTags(String input) {
        if (input == null) return null;
        String stripped = input.replaceAll("(?is)<[^>]*>", "");
        stripped = stripped.replaceAll("[\\p{Cntrl}&&[^\\n\\t]]", "");
        return stripped.trim();
    }

    public static boolean isValidEmail(String email) {
        return email != null && email.length() <= 254 && EMAIL_PATTERN.matcher(email).matches();
    }

    public static boolean isValidFilename(String filename) {
        if (filename == null || filename.isEmpty() || filename.length() > 255) return false;
        if (filename.contains("..") || filename.contains("/") || filename.contains("\\")) return false;
        return FILENAME_PATTERN.matcher(filename).matches();
    }

    public static boolean isStrongPassword(String password) {
        if (password == null || password.length() < 8 || password.length() > 64) return false;
        int types = 0;
        boolean hasLower = false, hasUpper = false, hasDigit = false, hasSpecial = false;
        for (char c : password.toCharArray()) {
            if (!hasLower && Character.isLowerCase(c)) { hasLower = true; types++; }
            if (!hasUpper && Character.isUpperCase(c)) { hasUpper = true; types++; }
            if (!hasDigit && Character.isDigit(c)) { hasDigit = true; types++; }
            if (!hasSpecial && !Character.isLetterOrDigit(c)) { hasSpecial = true; types++; }
        }
        return types >= 3;
    }

    public static String getPasswordRequirementMessage() {
        return "密码需8-64位，至少包含大小写字母、数字、特殊字符中的三种";
    }

    public static boolean isPathTraversalSafe(String filePath) {
        if (filePath == null) return false;
        return !filePath.contains("..")
                && !filePath.contains("./")
                && !filePath.contains("\\")
                && !filePath.contains("\0");
    }

    public static String safeFilename(String filename) {
        if (filename == null) return "unknown";
        return filename.replaceAll("[^a-zA-Z0-9_\\-\\u4e00-\\u9fa5.() ]", "_");
    }

    public static int safePage(int page) {
        return Math.max(0, page);
    }

    public static int safeSize(int size) {
        return Math.min(Math.max(1, size), 100);
    }
}
