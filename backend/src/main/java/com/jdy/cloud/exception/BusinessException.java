package com.jdy.cloud.exception;

import lombok.Getter;

import java.util.LinkedHashMap;
import java.util.Map;

@Getter
public class BusinessException extends RuntimeException {
    private final int code;
    /** IronWall v1.47.3: 真实冷却秒数（限流类异常），供 GlobalExceptionHandler 写 Retry-After。 */
    private final Long retryAfterSeconds;
    /** IronWall v1.47.3: 附加业务上下文（如剩余次数），随错误响应 data 透出。 */
    private final Map<String, Object> details;

    public BusinessException(int code, String message) {
        super(message);
        this.code = code;
        this.retryAfterSeconds = null;
        this.details = null;
    }

    public BusinessException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.code = errorCode.getCode();
        this.retryAfterSeconds = null;
        this.details = null;
    }

    public BusinessException(int code, String message, Long retryAfterSeconds) {
        super(message);
        this.code = code;
        this.retryAfterSeconds = retryAfterSeconds;
        this.details = null;
    }

    public BusinessException(int code, String message, Long retryAfterSeconds, Map<String, Object> details) {
        super(message);
        this.code = code;
        this.retryAfterSeconds = retryAfterSeconds;
        this.details = details == null ? null : new LinkedHashMap<>(details);
    }
}
