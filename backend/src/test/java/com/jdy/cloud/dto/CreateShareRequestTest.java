package com.jdy.cloud.dto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * IronWall v1.8: 前端旧打包发送 downloadLimit（驼峰），新打包发送 download_limit（下划线），
 * 两种键都必须能绑定到同一个字段，UI 设置的下载限次才不会被静默忽略为 -1。
 */
class CreateShareRequestTest {

    private final ObjectMapper mapper = new ObjectMapper()
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);

    @Test
    void shouldBindSnakeCaseDownloadLimit() throws Exception {
        CreateShareRequest request = mapper.readValue(
                "{\"file_id\":1,\"download_limit\":5}", CreateShareRequest.class);
        assertEquals(5, request.getDownloadLimit());
        assertEquals(1L, request.getFileId());
    }

    @Test
    void shouldBindCamelCaseDownloadLimitAlias() throws Exception {
        CreateShareRequest request = mapper.readValue(
                "{\"file_id\":1,\"downloadLimit\":7}", CreateShareRequest.class);
        assertEquals(7, request.getDownloadLimit());
    }

    @Test
    void shouldDefaultToZeroWhenMissing() throws Exception {
        CreateShareRequest request = mapper.readValue(
                "{\"file_id\":1}", CreateShareRequest.class);
        assertEquals(0, request.getDownloadLimit());
    }
}