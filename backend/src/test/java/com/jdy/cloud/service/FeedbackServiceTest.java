package com.jdy.cloud.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * IronWall v1.27.2: 反馈邮件 HTML 化与用户输入转义，防止邮件内容注入。
 */
class FeedbackServiceTest {

    @TempDir
    Path tempDir;

    @Test
    void submit_shouldSendHtmlEmailWithEscapedUserContent() {
        EmailService email = mock(EmailService.class);
        FeedbackService service = new FeedbackService(email, new ObjectMapper(),
                tempDir.resolve("feedback-records.json").toString(), true, 1L,
                "admin@example.com", "");

        String code = service.submit("203.0.113.9", "a@b.com", "<script>alert(1)</script> 测试内容正常");

        assertEquals("OK", code);
        ArgumentCaptor<String> htmlCaptor = ArgumentCaptor.forClass(String.class);
        verify(email).sendHtml(eq("admin@example.com"), anyString(), htmlCaptor.capture(), anyString());
        String html = htmlCaptor.getValue();
        assertFalse(html.contains("<script>"), "用户输入不应原样进入邮件 HTML");
        assertTrue(html.contains("&lt;script&gt;"), "用户输入应被 HTML 转义");
        assertTrue(html.contains("经典云网盘官方"), "邮件应包含官方抬头");
    }

    @Test
    void submit_shouldRejectTooShortContent() {
        FeedbackService service = new FeedbackService(mock(EmailService.class), new ObjectMapper(),
                tempDir.resolve("feedback-records.json").toString(), true, 600000L,
                "admin@example.com", "");
        assertEquals("INVALID", service.submit("203.0.113.10", "", "短"));
    }
}
