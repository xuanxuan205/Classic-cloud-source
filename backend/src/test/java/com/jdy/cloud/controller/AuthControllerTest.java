package com.jdy.cloud.controller;

import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.exception.GlobalExceptionHandler;
import com.jdy.cloud.repository.AnnouncementRepository;
import com.jdy.cloud.repository.UserRepository;
import com.jdy.cloud.security.UserPrincipal;
import com.jdy.cloud.security.DeviceIdentityResolver;
import com.jdy.cloud.service.AuthService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * IronWall v1.10: avatar upload endpoint contract tests.
 * valid multipart PNG -> 200 with avatarUrl (binding + success mapping)
 * empty file -> service rejects with BusinessException -> 400 via GlobalExceptionHandler
 * non-multipart POST -> MultipartException at binding -> 400 via GlobalExceptionHandler
 */
@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock private AuthService authService;
    @Mock private UserRepository userRepository;
    @Mock private AnnouncementRepository announcementRepository;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        AuthController controller = new AuthController(authService, userRepository, announcementRepository,
                new DeviceIdentityResolver(null));
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new GlobalExceptionHandler())
                .setCustomArgumentResolvers(new org.springframework.security.web.method.annotation.AuthenticationPrincipalArgumentResolver())
                .build();
        UserPrincipal principal = new UserPrincipal(1L, "tester", "user");
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(principal, null, java.util.List.of());
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void checkEmail_shouldReturnUnknownState_whenEmailFormatOk() throws Exception {
        mockMvc.perform(get("/api/auth/check-email").param("email", "taken@example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.format_ok").value(true))
                .andExpect(jsonPath("$.data.registered").value(org.hamcrest.Matchers.nullValue()));
        mockMvc.perform(get("/api/auth/check-email").param("email", "free@example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.format_ok").value(true))
                .andExpect(jsonPath("$.data.registered").value(org.hamcrest.Matchers.nullValue()));
    }

    @Test
    void checkEmail_shouldRejectBadFormat_with400() throws Exception {
        mockMvc.perform(get("/api/auth/check-email").param("email", "not-an-email"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void uploadAvatar_shouldReturn200_whenValidPng() throws Exception {
        byte[] png = new byte[]{(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4, 5, 6, 7, 8};
        MockMultipartFile avatar = new MockMultipartFile("avatar", "a.png", "image/png", png);
        when(authService.uploadAvatar(eq(1L), any(), isNull())).thenReturn("/api/files/avatar/avatar_1_1.png");
        mockMvc.perform(multipart("/api/auth/upload-avatar").file(avatar))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.avatarUrl").value("/api/files/avatar/avatar_1_1.png"));
    }

    @Test
    void uploadAvatar_shouldRejectEmptyFile_with400() throws Exception {
        MockMultipartFile avatar = new MockMultipartFile("avatar", "empty.png", "image/png", new byte[0]);
        when(authService.uploadAvatar(eq(1L), any(), isNull()))
                .thenThrow(new BusinessException(400, "\u4ec5\u652f\u6301\u56fe\u7247\u683c\u5f0f"));
        mockMvc.perform(multipart("/api/auth/upload-avatar").file(avatar))
                .andExpect(status().isBadRequest());
    }

    @Test
    void uploadAvatar_shouldRejectNonMultipart_with400() throws Exception {
        mockMvc.perform(post("/api/auth/upload-avatar"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void getPublicAnnouncements_shouldReturnStrippedEntries() throws Exception {
        com.jdy.cloud.model.Announcement a = new com.jdy.cloud.model.Announcement();
        a.setId(1L);
        a.setTitle("<b>维护通知</b>");
        a.setContent("第一行<script>alert(1)</script>\n第二行");
        a.setStatus("published");
        a.setCreatedAt(java.time.LocalDateTime.of(2026, 9, 2, 10, 0));
        when(announcementRepository.findByStatusOrderByCreatedAtDesc("pinned"))
                .thenReturn(java.util.List.of());
        when(announcementRepository.findByStatusOrderByCreatedAtDesc("published"))
                .thenReturn(java.util.List.of(a));

        mockMvc.perform(get("/api/auth/announcements"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(1))
                .andExpect(jsonPath("$.data[0].id").value(1))
                .andExpect(jsonPath("$.data[0].title").value("维护通知"))
                .andExpect(jsonPath("$.data[0].content").value("第一行alert(1)\n第二行"))
                .andExpect(jsonPath("$.data[0].status").value("published"))
                .andExpect(jsonPath("$.data[0].created_at").value("2026-09-02T10:00"));
    }

    @Test
    void getPublicAnnouncements_shouldPutPinnedFirst() throws Exception {
        com.jdy.cloud.model.Announcement pinned = new com.jdy.cloud.model.Announcement();
        pinned.setId(2L);
        pinned.setTitle("置顶公告");
        pinned.setContent("置顶内容");
        pinned.setStatus("pinned");
        pinned.setCreatedAt(java.time.LocalDateTime.of(2026, 9, 2, 11, 0));
        com.jdy.cloud.model.Announcement normal = new com.jdy.cloud.model.Announcement();
        normal.setId(1L);
        normal.setTitle("普通公告");
        normal.setContent("普通内容");
        normal.setStatus("published");
        normal.setCreatedAt(java.time.LocalDateTime.of(2026, 9, 2, 12, 0));
        when(announcementRepository.findByStatusOrderByCreatedAtDesc("pinned"))
                .thenReturn(java.util.List.of(pinned));
        when(announcementRepository.findByStatusOrderByCreatedAtDesc("published"))
                .thenReturn(java.util.List.of(normal));

        mockMvc.perform(get("/api/auth/announcements"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(2))
                .andExpect(jsonPath("$.data[0].id").value(2))
                .andExpect(jsonPath("$.data[0].status").value("pinned"))
                .andExpect(jsonPath("$.data[1].id").value(1))
                .andExpect(jsonPath("$.data[1].status").value("published"));
    }
}
