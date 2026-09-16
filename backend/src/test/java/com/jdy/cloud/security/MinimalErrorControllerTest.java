package com.jdy.cloud.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * IronWall v1.28.11: 错误响应不含框架签名。
 */
class MinimalErrorControllerTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void errorBodyIsMinimalJsonWithoutFrameworkSignatures() throws Exception {
        MinimalErrorController controller = new MinimalErrorController();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute("jakarta.servlet.error.status_code", 400);
        MockHttpServletResponse response = new MockHttpServletResponse();
        Map<String, Object> body = controller.handleError(request, response);
        assertEquals(400, response.getStatus());
        assertEquals(false, body.get("success"));
        assertEquals(400, body.get("code"));
        String json = mapper.writeValueAsString(body);
        assertFalse(json.toLowerCase().contains("tomcat"));
        assertFalse(json.toLowerCase().contains("spring"));
        assertFalse(json.toLowerCase().contains("exception"));
    }

    @Test
    void missingStatusFallsBackTo400() {
        MinimalErrorController controller = new MinimalErrorController();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        Map<String, Object> body = controller.handleError(request, response);
        assertEquals(400, response.getStatus());
        assertEquals(400, body.get("code"));
    }
}