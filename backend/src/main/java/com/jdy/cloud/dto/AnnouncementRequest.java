package com.jdy.cloud.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class AnnouncementRequest {
    @NotBlank(message = "标题不能为空")
    private String title;

    @NotBlank(message = "内容不能为空")
    private String content;

    private String status;

    // 定时发布（status=scheduled）时的发布时间，ISO 格式 yyyy-MM-ddTHH:mm[:ss]
    private String publishAt;
}
