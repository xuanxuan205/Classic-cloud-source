package com.jdy.cloud.service;

import com.jdy.cloud.dto.AnnouncementRequest;
import com.jdy.cloud.exception.BusinessException;
import com.jdy.cloud.model.Announcement;
import com.jdy.cloud.repository.AnnouncementRepository;
import com.jdy.cloud.repository.FileRepository;
import com.jdy.cloud.repository.FolderRepository;
import com.jdy.cloud.repository.LoginHistoryRepository;
import com.jdy.cloud.repository.ShareRepository;
import com.jdy.cloud.repository.UserRepository;
import com.jdy.cloud.security.TokenVersionService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * IronWall v1.45: 平台公告封顶 + 置顶/定时发布契约测试。
 * 发布第 11 条可见公告（置顶+已发布合计）时，物理删除最早的一条
 * 恰好 10 条时不删除；草稿/定时不触发封顶
 * 定时发布校验发布时间（缺失/格式/过去时间均拒绝）
 * 到期定时公告自动转 published，未到期不动
 */
@ExtendWith(MockitoExtension.class)
class AdminServiceAnnouncementCapTest {

    @Mock private UserRepository userRepository;
    @Mock private FileRepository fileRepository;
    @Mock private ShareRepository shareRepository;
    @Mock private AnnouncementRepository announcementRepository;
    @Mock private FolderRepository folderRepository;
    @Mock private LoginHistoryRepository loginHistoryRepository;
    @Mock private TokenVersionService tokenVersionService;
    @Mock private EmailService emailService;

    @InjectMocks
    private AdminService adminService;

    private List<Announcement> visibleList(int count, String status) {
        List<Announcement> list = new ArrayList<>();
        for (int i = 1; i <= count; i++) {
            Announcement a = new Announcement();
            a.setId((long) i);
            a.setTitle("公告" + i);
            a.setContent("内容" + i);
            a.setStatus(status);
            a.setCreatedAt(LocalDateTime.now().plusSeconds(i));
            list.add(a);
        }
        Collections.reverse(list); // created_at 降序（与仓储查询一致）
        return list;
    }

    private AnnouncementRequest request(String status) {
        return request(status, null);
    }

    private AnnouncementRequest request(String status, String publishAt) {
        AnnouncementRequest r = new AnnouncementRequest();
        r.setTitle("新公告");
        r.setContent("新公告内容");
        r.setStatus(status);
        r.setPublishAt(publishAt);
        return r;
    }

    @Test
    void create11thVisible_shouldDeleteOldestOne() {
        Announcement saved = new Announcement();
        saved.setId(11L);
        saved.setStatus("published");
        List<Announcement> existing = visibleList(11, "published");
        when(announcementRepository.save(any(Announcement.class))).thenReturn(saved);
        when(announcementRepository.findByStatusInOrderByCreatedAtDesc(anyList())).thenReturn(existing);

        adminService.createAnnouncement(1L, request("published"));

        Announcement oldest = existing.get(existing.size() - 1);
        assertEquals(1L, oldest.getId(), "最早的第 1 条公告必须被淘汰");
        verify(announcementRepository).delete(oldest);
        verify(announcementRepository, times(1)).delete(any(Announcement.class));
    }

    @Test
    void create10thVisible_shouldKeepAll() {
        Announcement saved = new Announcement();
        saved.setId(10L);
        saved.setStatus("pinned");
        when(announcementRepository.save(any(Announcement.class))).thenReturn(saved);
        when(announcementRepository.findByStatusInOrderByCreatedAtDesc(anyList()))
                .thenReturn(visibleList(10, "pinned"));

        adminService.createAnnouncement(1L, request("pinned"));

        verify(announcementRepository, never()).delete(any(Announcement.class));
    }

    @Test
    void createDraft_shouldNotCap() {
        Announcement saved = new Announcement();
        saved.setId(1L);
        saved.setStatus("draft");
        when(announcementRepository.save(any(Announcement.class))).thenReturn(saved);

        adminService.createAnnouncement(1L, request("draft"));

        verify(announcementRepository, never()).findByStatusInOrderByCreatedAtDesc(anyList());
        verify(announcementRepository, never()).delete(any(Announcement.class));
    }

    @Test
    void updateDraftToPublished_shouldCap() {
        Announcement draft = new Announcement();
        draft.setId(5L);
        draft.setStatus("draft");
        List<Announcement> existing = visibleList(11, "published");
        when(announcementRepository.findById(5L)).thenReturn(Optional.of(draft));
        when(announcementRepository.save(any(Announcement.class))).thenReturn(draft);
        when(announcementRepository.findByStatusInOrderByCreatedAtDesc(anyList())).thenReturn(existing);

        adminService.updateAnnouncement(5L, request("published"));

        assertEquals("published", draft.getStatus());
        verify(announcementRepository).delete(existing.get(existing.size() - 1));
    }

    @Test
    void createScheduled_shouldSetPublishAtAndNotCap() {
        Announcement saved = new Announcement();
        saved.setId(1L);
        saved.setStatus("scheduled");
        when(announcementRepository.save(any(Announcement.class))).thenReturn(saved);

        adminService.createAnnouncement(1L, request("scheduled", "2030-01-01T10:00:00"));

        ArgumentCaptor<Announcement> captor = ArgumentCaptor.forClass(Announcement.class);
        verify(announcementRepository).save(captor.capture());
        assertEquals(LocalDateTime.of(2030, 1, 1, 10, 0, 0), captor.getValue().getUpdatedAt());
        verify(announcementRepository, never()).findByStatusInOrderByCreatedAtDesc(anyList());
    }

    @Test
    void createScheduled_missingPublishAt_shouldThrow() {
        BusinessException ex = assertThrows(BusinessException.class,
                () -> adminService.createAnnouncement(1L, request("scheduled")));
        assertEquals("定时发布必须填写发布时间", ex.getMessage());
        verify(announcementRepository, never()).save(any(Announcement.class));
    }

    @Test
    void createScheduled_pastTime_shouldThrow() {
        BusinessException ex = assertThrows(BusinessException.class,
                () -> adminService.createAnnouncement(1L, request("scheduled", "2020-01-01T10:00:00")));
        assertEquals("定时发布时间必须晚于当前时间", ex.getMessage());
        verify(announcementRepository, never()).save(any(Announcement.class));
    }

    @Test
    void createScheduled_badFormat_shouldThrow() {
        BusinessException ex = assertThrows(BusinessException.class,
                () -> adminService.createAnnouncement(1L, request("scheduled", "not-a-time")));
        assertEquals("定时发布时间格式不正确", ex.getMessage());
        verify(announcementRepository, never()).save(any(Announcement.class));
    }

    @Test
    void publishDue_shouldPublishDueAndKeepFuture() {
        Announcement due = new Announcement();
        due.setId(1L);
        due.setStatus("scheduled");
        due.setUpdatedAt(LocalDateTime.now().minusMinutes(1));
        Announcement future = new Announcement();
        future.setId(2L);
        future.setStatus("scheduled");
        future.setUpdatedAt(LocalDateTime.now().plusHours(1));
        when(announcementRepository.findByStatus("scheduled")).thenReturn(List.of(due, future));
        when(announcementRepository.findByStatusInOrderByCreatedAtDesc(anyList())).thenReturn(List.of());

        adminService.publishDueAnnouncements();

        assertEquals("published", due.getStatus());
        assertEquals("scheduled", future.getStatus());
        verify(announcementRepository).save(due);
        verify(announcementRepository, never()).save(future);
        verify(announcementRepository, never()).delete(any(Announcement.class));
    }

    @Test
    void publishDue_noneScheduled_shouldReturnEarly() {
        when(announcementRepository.findByStatus("scheduled")).thenReturn(List.of());

        adminService.publishDueAnnouncements();

        verify(announcementRepository, never()).save(any(Announcement.class));
        verify(announcementRepository, never()).findByStatusInOrderByCreatedAtDesc(anyList());
    }
}