package com.jdy.cloud.controller;

import com.jdy.cloud.model.SystemConfig;
import com.jdy.cloud.repository.SystemConfigRepository;
import com.jdy.cloud.security.UploadPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Optional;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * IronWall v1.27.11: 公开站点信息接口契约测试。
 * 维护公告从 system_config 读取并原样返回；读取异常时回退为空字符串。
 */
@ExtendWith(MockitoExtension.class)
class SiteControllerTest {

    @Mock private SystemConfigRepository systemConfigRepository;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(new SiteController(systemConfigRepository)).build();
    }

    @Test
    void info_shouldExposeSiteNameAndMaintenanceNotice() throws Exception {
        SystemConfig notice = new SystemConfig();
        notice.setConfigKey("disabled_notice");
        notice.setConfigValue("<div><h3>系统维护中</h3></div>");
        when(systemConfigRepository.findByConfigKey("disabled_notice")).thenReturn(Optional.of(notice));
        when(systemConfigRepository.findByConfigKey("site_name")).thenReturn(Optional.empty());
        when(systemConfigRepository.findByConfigKey("site_description")).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/site/info"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.site_name").value("经典云网盘"))
                .andExpect(jsonPath("$.data.disabled_notice").value("<div><h3>系统维护中</h3></div>"));
    }

    /** IronWall v1.46.0: 上传阈值/策略版本随 site/info 下发，前端按服务端配置分流。 */
    @Test
    void info_shouldExposeUploadPolicyForFrontend() throws Exception {
        when(systemConfigRepository.findByConfigKey(anyString())).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/site/info"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.upload_direct_max_bytes").value(String.valueOf(UploadPolicy.DIRECT_UPLOAD_MAX_BYTES)))
                .andExpect(jsonPath("$.data.upload_chunk_size_bytes").value(String.valueOf(UploadPolicy.CHUNK_SIZE_BYTES)))
                .andExpect(jsonPath("$.data.upload_max_file_bytes").value(String.valueOf(UploadPolicy.MAX_FILE_BYTES)))
                .andExpect(jsonPath("$.data.upload_admin_max_file_bytes").value(String.valueOf(UploadPolicy.ADMIN_MAX_FILE_BYTES)))
                .andExpect(jsonPath("$.data.upload_policy_version").value(UploadPolicy.POLICY_VERSION))
                .andExpect(jsonPath("$.data.upload_ext_whitelist").value(org.hamcrest.Matchers.not(org.hamcrest.Matchers.emptyOrNullString())));
    }

    @Test
    void info_shouldFallbackToEmptyWhenReadFails() throws Exception {
        when(systemConfigRepository.findByConfigKey(anyString())).thenThrow(new RuntimeException("db down"));

        mockMvc.perform(get("/api/site/info"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.disabled_notice").value(""));
    }
}
