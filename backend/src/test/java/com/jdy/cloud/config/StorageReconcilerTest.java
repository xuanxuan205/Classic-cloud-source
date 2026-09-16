package com.jdy.cloud.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class StorageReconcilerTest {

    @Mock private JdbcTemplate jdbcTemplate;

    private StorageReconciler reconciler;

    @BeforeEach
    void setUp() {
        reconciler = new StorageReconciler(jdbcTemplate);
    }

    @Test
    void repairStorageCounters_shouldResetDriftedCounter() {
        when(jdbcTemplate.queryForList(contains("avatar_size"), eq(Long.class))).thenReturn(List.of(1L));
        when(jdbcTemplate.queryForObject(contains("SUM(file_size)"), eq(Long.class), eq(1L))).thenReturn(100L);
        when(jdbcTemplate.queryForObject(contains("avatar_size"), eq(Long.class), eq(1L))).thenReturn(50L);
        when(jdbcTemplate.update(contains("storage_used"), eq(150L), eq(1L), eq(150L))).thenReturn(1);

        int healed = reconciler.repairStorageCounters();

        assertEquals(1, healed);
        verify(jdbcTemplate).update(contains("storage_used"), eq(150L), eq(1L), eq(150L));
    }

    @Test
    void repairStorageCounters_shouldDoNothing_whenCountersConsistent() {
        when(jdbcTemplate.queryForList(contains("avatar_size"), eq(Long.class))).thenReturn(List.of());

        int healed = reconciler.repairStorageCounters();

        assertEquals(0, healed);
        verify(jdbcTemplate, never()).update(anyString(), any(), any(), any());
    }

    @Test
    void repairStorageCounters_shouldFallbackToFilesOnly_whenAvatarSizeColumnMissing() {
        when(jdbcTemplate.queryForList(contains("avatar_size"), eq(Long.class)))
                .thenThrow(new RuntimeException("Unknown column 'avatar_size'"));
        when(jdbcTemplate.queryForList(argThat((String s) -> s != null && !s.contains("avatar_size")), eq(Long.class)))
                .thenReturn(List.of(2L));
        when(jdbcTemplate.queryForObject(contains("SUM(file_size)"), eq(Long.class), eq(2L))).thenReturn(300L);
        when(jdbcTemplate.queryForObject(contains("avatar_size"), eq(Long.class), eq(2L)))
                .thenThrow(new RuntimeException("Unknown column 'avatar_size'"));
        when(jdbcTemplate.update(contains("storage_used"), eq(300L), eq(2L), eq(300L))).thenReturn(1);

        int healed = reconciler.repairStorageCounters();

        assertEquals(1, healed);
        verify(jdbcTemplate).update(contains("storage_used"), eq(300L), eq(2L), eq(300L));
    }

    @Test
    void repairStorageCounters_shouldNotCrash_whenSingleRepairFails() {
        when(jdbcTemplate.queryForList(contains("avatar_size"), eq(Long.class))).thenReturn(List.of(3L));
        when(jdbcTemplate.queryForObject(contains("SUM(file_size)"), eq(Long.class), eq(3L))).thenReturn(10L);
        when(jdbcTemplate.queryForObject(contains("avatar_size"), eq(Long.class), eq(3L))).thenReturn(0L);
        when(jdbcTemplate.update(contains("storage_used"), eq(10L), eq(3L), eq(10L)))
                .thenThrow(new RuntimeException("db down"));

        assertEquals(0, reconciler.repairStorageCounters());
    }
}