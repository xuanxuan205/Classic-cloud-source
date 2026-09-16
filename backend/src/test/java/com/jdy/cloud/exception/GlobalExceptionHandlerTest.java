package com.jdy.cloud.exception;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.multipart.MultipartException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Map;

/**
 * IronWall v1.10: status mapping contract for the global exception handler.
 */
class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void handleBusinessException_shouldMapBadRequest() {
        var resp = handler.handleBusinessException(new BusinessException(400, "bad input"));
        assertEquals(HttpStatus.BAD_REQUEST, resp.getStatusCode());
    }

    @Test
    void handleMultipart_shouldMapBadRequest() {
        var resp = handler.handleMultipart(new MultipartException("Current request is not a multipart request"));
        assertEquals(HttpStatus.BAD_REQUEST, resp.getStatusCode());
    }

    @Test
    void handleNoResource_shouldMap404() {
        var resp = handler.handleNoResource(new NoResourceFoundException(HttpMethod.GET, "/api/Admin/dashboard"));
        assertEquals(HttpStatus.NOT_FOUND, resp.getStatusCode());
    }

    @Test
    void handleBusinessException_shouldMapBannedTo403() {
        var resp = handler.handleBusinessException(new BusinessException(ErrorCode.ACCOUNT_BANNED.getCode(), ErrorCode.ACCOUNT_BANNED.getMessage()));
        assertEquals(HttpStatus.FORBIDDEN, resp.getStatusCode());
    }

    // IronWall v1.47.0: 错误密码必须返回 400 + code=3004（前端按 code 分类，不再猜 message）
    @Test
    void handleBusinessException_shouldMapWrongSharePasswordTo400WithCode() {
        var resp = handler.handleBusinessException(new BusinessException(ErrorCode.SHARE_WRONG_PASSWORD));
        assertEquals(HttpStatus.BAD_REQUEST, resp.getStatusCode());
        assertNotNull(resp.getBody());
        assertEquals(ErrorCode.SHARE_WRONG_PASSWORD.getCode(), resp.getBody().getCode());
        assertEquals(ErrorCode.SHARE_WRONG_PASSWORD.getMessage(), resp.getBody().getMessage());
        assertFalse(resp.getBody().isSuccess());
    }

    // IronWall v1.47.0: 分享限流 429 必须带 Retry-After，前端可退避重试而非误判失效
    // IronWall v1.47.3: 429 must carry the real cooldown seconds from the limiter
    @Test
    void handleBusinessException_shouldUseCarriedRetryAfter() {
        var resp = handler.handleBusinessException(new BusinessException(
                ErrorCode.TOO_MANY_REQUESTS.getCode(), "throttled", 37L, Map.of("retry_after", 37L)));
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, resp.getStatusCode());
        assertEquals("37", resp.getHeaders().getFirst("Retry-After"));
        assertEquals(ErrorCode.TOO_MANY_REQUESTS.getCode(), resp.getBody().getCode());
    }

    // IronWall v1.47.3: business details (remaining quota) are exposed in response data
    @Test
    void handleBusinessException_shouldExposeDetailsInData() {
        var resp = handler.handleBusinessException(new BusinessException(
                ErrorCode.SHARE_LIMIT_REACHED.getCode(), ErrorCode.SHARE_LIMIT_REACHED.getMessage(),
                null, Map.of("download_count", 1, "download_limit", 1, "remaining", 0)));
        assertEquals(HttpStatus.BAD_REQUEST, resp.getStatusCode());
        assertNotNull(resp.getBody());
        assertEquals(ErrorCode.SHARE_LIMIT_REACHED.getCode(), resp.getBody().getCode());
        assertNotNull(resp.getBody().getData());
        assertEquals(0, ((Map<?, ?>) resp.getBody().getData()).get("remaining"));
    }

    @Test
    void handleBusinessException_shouldMapShareThrottleTo429WithRetryAfter() {
        var resp = handler.handleBusinessException(new BusinessException(ErrorCode.TOO_MANY_REQUESTS));
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, resp.getStatusCode());
        assertEquals("60", resp.getHeaders().getFirst("Retry-After"));
        assertNotNull(resp.getBody());
        assertEquals(ErrorCode.TOO_MANY_REQUESTS.getCode(), resp.getBody().getCode());
    }
}
