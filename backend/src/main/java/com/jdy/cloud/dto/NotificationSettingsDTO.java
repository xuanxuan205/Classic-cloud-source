package com.jdy.cloud.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * IronWall v1.47.10: 通知设置读写契约单一化。
 *
 * 本 DTO 同时用于响应（GET）与请求（PUT）。后端全局 SNAKE_CASE：
 * 序列化侧用 @JsonProperty 显式锁定 snake_case，不再依赖全局策略，避免响应键名漂移；
 * 反序列化侧用 @JsonAlias 同时接受 snake_case 与 camelCase，兼容新旧前端包。
 */
@Data
public class NotificationSettingsDTO {
    @JsonProperty("email_notify")
    @JsonAlias("emailNotify")
    private Boolean emailNotify;

    @JsonProperty("browser_notify")
    @JsonAlias("browserNotify")
    private Boolean browserNotify;

    @JsonProperty("storage_alert")
    @JsonAlias("storageAlert")
    private Boolean storageAlert;

    @JsonProperty("share_notify")
    @JsonAlias("shareNotify")
    private Boolean shareNotify;
}
