package com.jdy.cloud.dto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IronWall v1.47.10: 通知设置读写契约回归门禁。
 *
 * 旧实现只用 @JsonAlias 声明 camelCase，序列化仍随全局 SNAKE_CASE 输出 snake_case，
 * 而前端按 camelCase 读取 → 开关状态永远读不回来、再次保存还会把默认值写回。
 * 这里同时锁定两个方向：输出必须是 snake_case，输入必须两种命名都能接受。
 */
class NotificationSettingsDtoContractTest {

    private final ObjectMapper mapper = new ObjectMapper()
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);

    /** 响应必须是 snake_case——前端按 email_notify 等键名读取。 */
    @Test
    void serialization_shouldEmitSnakeCaseKeys() throws Exception {
        NotificationSettingsDTO dto = new NotificationSettingsDTO();
        dto.setEmailNotify(true);
        dto.setBrowserNotify(false);
        dto.setStorageAlert(true);
        dto.setShareNotify(true);

        JsonNode node = mapper.readTree(mapper.writeValueAsString(dto));

        assertTrue(node.has("email_notify"), "响应必须含 email_notify");
        assertTrue(node.has("browser_notify"), "响应必须含 browser_notify");
        assertTrue(node.has("storage_alert"), "响应必须含 storage_alert");
        assertTrue(node.has("share_notify"), "响应必须含 share_notify");
        assertFalse(node.has("emailNotify"), "响应不得再出现 camelCase 键名");
        assertFalse(node.has("browserNotify"), "响应不得再出现 camelCase 键名");
        assertFalse(node.has("storageAlert"), "响应不得再出现 camelCase 键名");
        assertFalse(node.has("shareNotify"), "响应不得再出现 camelCase 键名");
        assertTrue(node.get("email_notify").asBoolean());
        assertFalse(node.get("browser_notify").asBoolean());
    }

    /** 请求侧仍兼容新旧前端打包：snake_case 与 camelCase 都能写入。 */
    @Test
    void deserialization_shouldAcceptBothConventions() throws Exception {
        NotificationSettingsDTO snake = mapper.readValue(
                "{\"email_notify\":false,\"browser_notify\":false,\"storage_alert\":false,\"share_notify\":true}",
                NotificationSettingsDTO.class);
        assertEquals(Boolean.FALSE, snake.getEmailNotify());
        assertEquals(Boolean.FALSE, snake.getBrowserNotify());
        assertEquals(Boolean.FALSE, snake.getStorageAlert());
        assertEquals(Boolean.TRUE, snake.getShareNotify());

        NotificationSettingsDTO camel = mapper.readValue(
                "{\"emailNotify\":true,\"browserNotify\":false,\"storageAlert\":true,\"shareNotify\":false}",
                NotificationSettingsDTO.class);
        assertEquals(Boolean.TRUE, camel.getEmailNotify());
        assertEquals(Boolean.FALSE, camel.getBrowserNotify());
        assertEquals(Boolean.TRUE, camel.getStorageAlert());
        assertEquals(Boolean.FALSE, camel.getShareNotify());
    }
}
