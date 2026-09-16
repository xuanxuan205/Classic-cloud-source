package com.jdy.cloud.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class FileUploadResult {
    private Long id;
    private String filename;
    @JsonProperty("original_name")
    private String originalName;
    @JsonProperty("file_size")
    private Long fileSize;
    @JsonProperty("file_type")
    private String fileType;
    @JsonProperty("mime_type")
    private String mimeType;
    @JsonProperty("folder_id")
    private Long folderId;
    @JsonProperty("download_count")
    private int downloadCount;
    @JsonProperty("created_at")
    private String createdAt;
}
