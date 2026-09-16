package com.jdy.cloud.exception;

import com.jdy.cloud.dto.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import jakarta.validation.ConstraintViolationException;

import java.util.stream.Collectors;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

        @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ApiResponse<Object>> handleBusinessException(BusinessException e) {
        log.warn("Business exception: code={} message={}", e.getCode(), e.getMessage());
        HttpStatus status = mapCodeToHttpStatus(e.getCode());
        log.warn("Mapped code {} -> HTTP {}", e.getCode(), status.value());
        ResponseEntity.BodyBuilder builder = ResponseEntity.status(status);
        // IronWall v1.47.3: 429 Retry-After reflects the real cooldown carried by the exception
        if (status == HttpStatus.TOO_MANY_REQUESTS) {
            long retryAfter = e.getRetryAfterSeconds() != null && e.getRetryAfterSeconds() > 0
                    ? Math.min(e.getRetryAfterSeconds(), 3600L) : 60L;
            builder.header("Retry-After", String.valueOf(retryAfter));
        }
        ApiResponse<Object> body = ApiResponse.error(e.getCode(), e.getMessage());
        if (e.getDetails() != null && !e.getDetails().isEmpty()) {
            body.setData(e.getDetails());
        }
        return builder.body(body);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Void>> handleValidation(MethodArgumentNotValidException e) {
        String message = e.getBindingResult().getFieldErrors().stream()
                .map(FieldError::getDefaultMessage)
                .collect(Collectors.joining("; "));
        return ResponseEntity.badRequest()
                .body(ApiResponse.error(ErrorCode.BAD_REQUEST.getCode(), message));
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiResponse<Void>> handleMethodNotSupported(HttpRequestMethodNotSupportedException e) {
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED)
                .body(ApiResponse.error(405, "Request method not supported"));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponse<Void>> handleBadCredentials() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.error(ErrorCode.WRONG_PASSWORD.getCode(), "Username or password error"));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<Void>> handleAccessDenied() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(ApiResponse.error(ErrorCode.FORBIDDEN.getCode(), ErrorCode.FORBIDDEN.getMessage()));
    }

    // IronWall v1.10: non-multipart / broken multipart avatar uploads must be 400, never 500
    @ExceptionHandler(MultipartException.class)
    public ResponseEntity<ApiResponse<Void>> handleMultipart(MultipartException e) {
        log.warn("Multipart request invalid: {}", e.getMessage());
        return ResponseEntity.badRequest()
                .body(ApiResponse.error(ErrorCode.BAD_REQUEST.getCode(), "\u8bf7\u6c42\u5fc5\u987b\u662f multipart/form-data \u4e14\u5305\u542b\u6587\u4ef6"));
    }

    // IronWall v1.10: multipart form missing the required file part -> 400, never 500
    @ExceptionHandler(MissingServletRequestPartException.class)
    public ResponseEntity<ApiResponse<Void>> handleMissingPart(MissingServletRequestPartException e) {
        return ResponseEntity.badRequest()
                .body(ApiResponse.error(ErrorCode.BAD_REQUEST.getCode(), "Missing file parameter"));
    }
    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<ApiResponse<Void>> handleMaxUploadSize() {
        return ResponseEntity.badRequest()
                .body(ApiResponse.error(ErrorCode.FILE_TOO_LARGE.getCode(), ErrorCode.FILE_TOO_LARGE.getMessage()));
    }

    // IronWall v1.2: 超大数字ID等类型转换错误返回400而非500
    // IronWall v1.3: 畸形 JSON 请求体 -> 400
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResponse<Void>> handleUnreadable(HttpMessageNotReadableException e) {
        log.warn("Malformed request body: {}", e.getMessage());
        return ResponseEntity.badRequest()
                .body(ApiResponse.error(ErrorCode.BAD_REQUEST.getCode(), "请求体格式错误（JSON解析失败）"));
    }

    // IronWall v1.3: 缺少必填参数 -> 400
    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ApiResponse<Void>> handleMissingParam(MissingServletRequestParameterException e) {
        return ResponseEntity.badRequest()
                .body(ApiResponse.error(ErrorCode.BAD_REQUEST.getCode(), "Missing required parameter"));
    }

    // IronWall v1.3: 不支持的 Content-Type -> 415
    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ApiResponse<Void>> handleMediaType(HttpMediaTypeNotSupportedException e) {
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                .body(ApiResponse.error(415, "不支持的Content-Type"));
    }

    // IronWall v1.3: 参数约束校验失败 -> 400
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiResponse<Void>> handleConstraint(ConstraintViolationException e) {
        String message = e.getConstraintViolations().stream()
                .map(v -> v.getMessage())
                .collect(Collectors.joining("; "));
        return ResponseEntity.badRequest()
                .body(ApiResponse.error(ErrorCode.BAD_REQUEST.getCode(), message));
    }

    // IronWall v1.9: 未匹配任何路由/静态资源的路径（含 /api/admin 大小写变体）统一 404 JSON，
    // 不再落入兜底 Exception 处理变成 500，杜绝用 500 探测端点存在性
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleNoResource(NoResourceFoundException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ApiResponse.error(ErrorCode.NOT_FOUND.getCode(), ErrorCode.NOT_FOUND.getMessage()));
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ApiResponse<Void>> handleTypeMismatch(MethodArgumentTypeMismatchException e) {
        log.warn("Type mismatch: param={} value={}", e.getName(), e.getValue());
        return ResponseEntity.badRequest()
                .body(ApiResponse.error(ErrorCode.BAD_REQUEST.getCode(), "Invalid parameter format"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGeneral(Exception e) {
        log.error("Unexpected error", e);
        return ResponseEntity.internalServerError()
                .body(ApiResponse.error(ErrorCode.INTERNAL_ERROR.getCode(), ErrorCode.INTERNAL_ERROR.getMessage()));
    }

    private HttpStatus mapCodeToHttpStatus(int code) {
        // 5xx server errors
        if (code == 500) return HttpStatus.INTERNAL_SERVER_ERROR;
        // 429 rate limit
        if (code == 429 || code == 1011) return HttpStatus.TOO_MANY_REQUESTS;
        // 401 auth errors (unauthenticated, wrong password, locked, invalid/expired token)
        if (code == 401) return HttpStatus.UNAUTHORIZED;
        if (code == 1004 || code == 1005 || code == 1006 || code == 1007 || code == 1008)
            return HttpStatus.UNAUTHORIZED;
        // 403 forbidden（含分享下载凭证无效/过期，与错误 sig 同响应、无侧信道）
        if (code == 403 || code == 4001 || code == 1012 || code == 3007) return HttpStatus.FORBIDDEN;
        // 409 conflict (duplicate username/email)
        if (code == 409 || code == 1002 || code == 1003) return HttpStatus.CONFLICT;
        // 404 not found (user/file/share/folder not found)
        if (code == 404 || (code >= 2000 && code < 3000)) return HttpStatus.NOT_FOUND;
        // Share error codes -> 400
        if (code >= 3000 && code < 4000) return HttpStatus.BAD_REQUEST;
        // Default: 400 for validation/code errors
        return HttpStatus.BAD_REQUEST;
    }
}
