package com.jdy.cloud.controller;

import com.jdy.cloud.security.AttackGuardService;
import com.jdy.cloud.security.CanaryService;
import com.jdy.cloud.security.HoneypotLayerService;
import com.jdy.cloud.security.TrapService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * IronWall v1.18: 五层蜜罐诱捕端点契约测试。
 * L1 路径蜜罐返回仿真内容；L2~L4 分层端点返回各自层级内容并逐层记分。
 */
@ExtendWith(MockitoExtension.class)
class HoneypotControllerTest {

    @Mock private AttackGuardService attackGuardService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        CanaryService canaryService = new CanaryService("test-canary");
        HoneypotLayerService layerService = new HoneypotLayerService(attackGuardService);
        TrapService trapService = mock(TrapService.class);
        HoneypotController controller = new HoneypotController(canaryService, layerService, trapService);
        ReflectionTestUtils.setField(controller, "honeypotEnabled", true);
        ReflectionTestUtils.setField(controller, "slowChunkMillis", 0L);
        ReflectionTestUtils.setField(controller, "slowChunks", 4);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    void l6Storage_shouldReturnFakeBucketsAndTrapLayer6() throws Exception {
        CanaryService canaryService = new CanaryService("test-canary");
        HoneypotLayerService layerService = new HoneypotLayerService(attackGuardService);
        TrapService trapService = mock(TrapService.class);
        HoneypotController controller = new HoneypotController(canaryService, layerService, trapService);
        ReflectionTestUtils.setField(controller, "honeypotEnabled", true);
        ReflectionTestUtils.setField(controller, "slowChunkMillis", 0L);
        ReflectionTestUtils.setField(controller, "slowChunks", 4);
        MockMvc mvc = MockMvcBuilders.standaloneSetup(controller).build();

        mvc.perform(get("/api/honeypot/storage").with(request -> {
                    request.setRemoteAddr("203.0.113.76");
                    return request;
                }))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("buckets")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("IronWall.Canary.test-canary")));

        verify(attackGuardService).recordWeighted(eq("203.0.113.76"), eq(AttackGuardService.TYPE_HONEYPOT),
                contains("第6层"), eq("/api/honeypot/storage"), any(), eq("GET"), eq(false), eq(30));
        verify(trapService).trap(eq("203.0.113.76"), eq(6), anyString(), eq("/api/honeypot/storage"), any(), eq("GET"), eq(false));
    }

    @Test
    void l7Gateway_shouldReturnFakeGatewayAndTrapLayer7() throws Exception {
        CanaryService canaryService = new CanaryService("test-canary");
        HoneypotLayerService layerService = new HoneypotLayerService(attackGuardService);
        TrapService trapService = mock(TrapService.class);
        HoneypotController controller = new HoneypotController(canaryService, layerService, trapService);
        ReflectionTestUtils.setField(controller, "honeypotEnabled", true);
        ReflectionTestUtils.setField(controller, "slowChunkMillis", 0L);
        ReflectionTestUtils.setField(controller, "slowChunks", 4);
        MockMvc mvc = MockMvcBuilders.standaloneSetup(controller).build();

        mvc.perform(get("/api/honeypot/gateway").with(request -> {
                    request.setRemoteAddr("203.0.113.77");
                    return request;
                }))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Ops Gateway")));

        verify(attackGuardService).recordWeighted(eq("203.0.113.77"), eq(AttackGuardService.TYPE_HONEYPOT),
                contains("第7层"), eq("/api/honeypot/gateway"), any(), eq("GET"), eq(false), eq(35));
        verify(trapService).trap(eq("203.0.113.77"), eq(7), anyString(), eq("/api/honeypot/gateway"), any(), eq("GET"), eq(false));
    }

    @Test
    void envDecoy_shouldReturnFakeEnvWithCanaryAndRecordAttack() throws Exception {
        mockMvc.perform(get("/api/.env").with(request -> {
                    request.setRemoteAddr("203.0.113.60");
                    return request;
                }))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("IronWall.Canary.test-canary")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("DB_PASSWORD")));

        verify(attackGuardService).recordWeighted(eq("203.0.113.60"), eq(AttackGuardService.TYPE_HONEYPOT),
                contains("第1层"), eq("/api/.env"), any(), eq("GET"), eq(false), eq(5));
    }

    @Test
    void loginDecoy_shouldReturnFakeLoginPage() throws Exception {
        mockMvc.perform(post("/api/legacy/admin/login").with(request -> {
                    request.setRemoteAddr("203.0.113.61");
                    return request;
                }))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Sign in")));

        verify(attackGuardService).recordWeighted(eq("203.0.113.61"), eq(AttackGuardService.TYPE_HONEYPOT),
                anyString(), eq("/api/legacy/admin/login"), any(), eq("POST"), eq(false), eq(5));
    }

    @Test
    void actuatorDecoy_shouldReturnFakeJsonWithCanary() throws Exception {
        mockMvc.perform(get("/api/actuator/env").with(request -> {
                    request.setRemoteAddr("203.0.113.62");
                    return request;
                }))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("IronWall.Canary.test-canary")));

        verify(attackGuardService).recordWeighted(eq("203.0.113.62"), eq(AttackGuardService.TYPE_HONEYPOT),
                anyString(), eq("/api/actuator/env"), any(), eq("GET"), eq(false), eq(5));
    }

    @Test
    void l2Login_shouldReturnFakeFormAndRecordLayer2() throws Exception {
        mockMvc.perform(get("/api/honeypot/login").with(request -> {
                    request.setRemoteAddr("203.0.113.70");
                    return request;
                }))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Management Console")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("IronWall.Canary.test-canary")));

        verify(attackGuardService).recordWeighted(eq("203.0.113.70"), eq(AttackGuardService.TYPE_HONEYPOT),
                contains("第2层"), eq("/api/honeypot/login"), any(), eq("GET"), eq(false), eq(10));
    }

    @Test
    void l2LoginPost_shouldReturnFailureWithNewCanary() throws Exception {
        mockMvc.perform(post("/api/honeypot/login").with(request -> {
                    request.setRemoteAddr("203.0.113.71");
                    return request;
                }))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("登录失败")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("IronWall.Canary.test-canary")));

        verify(attackGuardService).recordWeighted(eq("203.0.113.71"), eq(AttackGuardService.TYPE_HONEYPOT),
                contains("第2层"), eq("/api/honeypot/login"), any(), eq("POST"), eq(false), eq(10));
    }

    @Test
    void l3Console_shouldReturnDashboardAndRecordLayer3() throws Exception {
        mockMvc.perform(get("/api/honeypot/console").with(request -> {
                    request.setRemoteAddr("203.0.113.72");
                    return request;
                }))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Ops Console")));

        verify(attackGuardService).recordWeighted(eq("203.0.113.72"), eq(AttackGuardService.TYPE_HONEYPOT),
                contains("第3层"), eq("/api/honeypot/console"), any(), eq("GET"), eq(false), eq(15));
    }

    @Test
    void l3ConsoleUsers_shouldReturnFakeUsersJson() throws Exception {
        mockMvc.perform(get("/api/honeypot/console/api/users").with(request -> {
                    request.setRemoteAddr("203.0.113.73");
                    return request;
                }))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("superadmin")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("IronWall.Canary.test-canary")));

        verify(attackGuardService).recordWeighted(eq("203.0.113.73"), eq(AttackGuardService.TYPE_HONEYPOT),
                contains("第3层"), eq("/api/honeypot/console/api/users"), any(), eq("GET"), eq(false), eq(15));
    }

    @Test
    void l4Dump_shouldReturnDumpChunksAndRecordLayer4() throws Exception {
        mockMvc.perform(get("/api/honeypot/dump.sql").with(request -> {
                    request.setRemoteAddr("203.0.113.74");
                    return request;
                }))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("decoy")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("IronWall.Canary.test-canary")));

        verify(attackGuardService).recordWeighted(eq("203.0.113.74"), eq(AttackGuardService.TYPE_HONEYPOT),
                contains("第4层"), eq("/api/honeypot/dump.sql"), any(), eq("GET"), eq(false), eq(20));
    }

    @Test
    void l4Backup_shouldReturnBackupChunksAndRecordLayer4() throws Exception {
        mockMvc.perform(get("/api/honeypot/backup.zip").with(request -> {
                    request.setRemoteAddr("203.0.113.75");
                    return request;
                }))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("decoy archive")));

        verify(attackGuardService).recordWeighted(eq("203.0.113.75"), eq(AttackGuardService.TYPE_HONEYPOT),
                contains("第4层"), eq("/api/honeypot/backup.zip"), any(), eq("GET"), eq(false), eq(20));
    }

    @Test
    void disabledHoneypot_shouldReturn404WithoutRecording() throws Exception {
        CanaryService canaryService = new CanaryService("test-canary");
        HoneypotLayerService layerService = new HoneypotLayerService(attackGuardService);
        TrapService trapService = mock(TrapService.class);
        HoneypotController controller = new HoneypotController(canaryService, layerService, trapService);
        ReflectionTestUtils.setField(controller, "honeypotEnabled", false);
        MockMvc disabled = MockMvcBuilders.standaloneSetup(controller).build();

        disabled.perform(get("/api/.env").with(request -> {
                    request.setRemoteAddr("203.0.113.63");
                    return request;
                }))
                .andExpect(status().isNotFound());

        disabled.perform(get("/api/honeypot/login").with(request -> {
                    request.setRemoteAddr("203.0.113.63");
                    return request;
                }))
                .andExpect(status().isNotFound());

        verify(attackGuardService, never()).recordWeighted(anyString(), anyString(), anyString(), anyString(), any(), anyString(), anyBoolean(), anyInt());
    }
}
