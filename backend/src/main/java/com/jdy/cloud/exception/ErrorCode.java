package com.jdy.cloud.exception;

public enum ErrorCode {
    SUCCESS(200, "操作成功"),
    BAD_REQUEST(400, "请求参数错误"),
    UNAUTHORIZED(401, "未授权，请先登录"),
    FORBIDDEN(403, "权限不足"),
    NOT_FOUND(404, "资源不存在"),
    CONFLICT(409, "资源冲突"),
    TOO_MANY_REQUESTS(429, "请求过于频繁，请稍后再试"),
    INTERNAL_ERROR(500, "服务器内部错误"),
    USER_NOT_FOUND(1001, "用户不存在"),
    USERNAME_EXISTS(1002, "用户名已存在"),
    EMAIL_EXISTS(1003, "邮箱已被注册"),
    WRONG_PASSWORD(1004, "密码错误"),
        ACCOUNT_LOCKED(1005, "账户已被锁定，请稍后再试"),
    ACCOUNT_BANNED(1012, "账号已被封禁，请联系管理员"),
    ACCOUNT_NOT_VERIFIED(1006, "账户未验证"),
    INVALID_TOKEN(1007, "无效的认证令牌"),
    TOKEN_EXPIRED(1008, "认证令牌已过期"),
    CODE_ERROR(1009, "验证码错误"),
    CODE_EXPIRED(1010, "验证码已过期"),
    CODE_TOO_FREQUENT(1011, "验证码发送过于频繁"),
    FILE_NOT_FOUND(2001, "文件不存在"),
    FILE_UPLOAD_FAILED(2002, "文件上传失败"),
    FILE_TOO_LARGE(2003, "文件大小超出限制"),
    STORAGE_FULL(2004, "存储空间不足"),
    FOLDER_NOT_FOUND(2005, "文件夹不存在"),
    FOLDER_NOT_EMPTY(2006, "文件夹不为空"),
    SHARE_NOT_FOUND(3001, "分享不存在"),
    SHARE_EXPIRED(3002, "分享已过期"),
    SHARE_NEED_PASSWORD(3003, "需要提取密码"),
    SHARE_WRONG_PASSWORD(3004, "提取密码错误"),
    SHARE_LIMIT_REACHED(3005, "下载次数已达上限"),
    SHARE_BANNED(3006, "该分享因违规行为已被封禁"),
    SHARE_SIG_INVALID(3007, "下载凭证无效或已过期"),
    FILE_TYPE_NOT_ALLOWED(4002, "该类型文件暂不支持上传"),
    ADMIN_REQUIRED(4001, "需要管理员权限");

    private final int code;
    private final String message;

    ErrorCode(int code, String message) {
        this.code = code;
        this.message = message;
    }

    public int getCode() { return code; }
    public String getMessage() { return message; }
}
