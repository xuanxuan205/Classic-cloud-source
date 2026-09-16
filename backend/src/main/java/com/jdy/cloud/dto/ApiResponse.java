package com.jdy.cloud.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> {
    private boolean success;
    private String message;
    private Integer code;
    private T data;

    public ApiResponse() {}

    public ApiResponse(boolean success, String message, T data) {
        this.success = success;
        this.message = message;
        this.data = data;
    }

    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    public Integer getCode() { return code; }
    public void setCode(Integer code) { this.code = code; }
    public T getData() { return data; }
    public void setData(T data) { this.data = data; }

    public static <T> ApiResponse<T> ok(T data) {
        return new ApiResponse<>(true, "操作成功", data);
    }

    public static <T> ApiResponse<T> ok(String message, T data) {
        return new ApiResponse<>(true, message, data);
    }

    public static ApiResponse<Void> ok() {
        return new ApiResponse<>(true, "操作成功", null);
    }

    // IronWall v1.47.0: 错误响应携带业务码，前端按 code 精准分类（密码/封禁/失效/瞬时），
    // 不再依赖 message 文案关键词，杜绝「签名拒绝/限流」被误判为「分享已失效」。
    public static <T> ApiResponse<T> error(int code, String message) {
        ApiResponse<T> response = new ApiResponse<>(false, message, null);
        response.setCode(code);
        return response;
    }
}
