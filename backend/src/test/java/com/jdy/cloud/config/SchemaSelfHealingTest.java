package com.jdy.cloud.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** IronWall v1.47.6: 靓号固定性自愈——已有号不改、管理员固定 99999、随机池保留 99999。 */
@ExtendWith(MockitoExtension.class)
class SchemaSelfHealingTest {

    @Mock
    private JdbcTemplate jdbcTemplate;

    private SchemaSelfHealing healing;

    @BeforeEach
    void setUp() {
        healing = new SchemaSelfHealing(jdbcTemplate);
    }

    private static String sql(java.util.function.Predicate<String> match) {
        return argThat(s -> s != null && match.test(s));
    }

    @Test
    void run_shouldFixAdminCodeTo99999() {
        when(jdbcTemplate.queryForList(anyString(), eq(String.class))).thenReturn(List.of("00001"));
        when(jdbcTemplate.queryForList(sql(s -> s.contains("user_code = '99999'") && s.contains("<> 'admin'")), eq(Long.class))).thenReturn(List.of());
        when(jdbcTemplate.queryForList(sql(s -> s.contains("user_code = '99999'") && s.contains("= 'admin' ORDER BY id LIMIT 1")), eq(Long.class))).thenReturn(List.of());
        when(jdbcTemplate.queryForList(sql(s -> !s.contains("user_code = '99999'") && s.contains("'admin' ORDER BY id")), eq(Long.class))).thenReturn(List.of(7L));
        when(jdbcTemplate.queryForList(sql(s -> s.contains("user_code IS NULL OR user_code = ''")), eq(Long.class))).thenReturn(List.of());
        when(jdbcTemplate.update(eq("UPDATE users SET user_code='99999' WHERE id=?"), eq(7L))).thenReturn(1);

        healing.run(new org.springframework.boot.DefaultApplicationArguments());

        verify(jdbcTemplate).update(eq("UPDATE users SET user_code='99999' WHERE id=?"), eq(7L));
    }

    @Test
    void run_shouldBackfillLegacyUsers_withoutUsing99999() {
        when(jdbcTemplate.queryForList(anyString(), eq(String.class))).thenReturn(List.of("00001"));
        when(jdbcTemplate.queryForList(sql(s -> s.contains("user_code = '99999'") && s.contains("<> 'admin'")), eq(Long.class))).thenReturn(List.of());
        when(jdbcTemplate.queryForList(sql(s -> s.contains("user_code = '99999'") && s.contains("= 'admin' ORDER BY id LIMIT 1")), eq(Long.class))).thenReturn(List.of());
        when(jdbcTemplate.queryForList(sql(s -> !s.contains("user_code = '99999'") && s.contains("'admin' ORDER BY id")), eq(Long.class))).thenReturn(List.of());
        when(jdbcTemplate.queryForList(sql(s -> s.contains("user_code IS NULL OR user_code = ''")), eq(Long.class))).thenReturn(List.of(1L, 2L));
        when(jdbcTemplate.update(contains("UPDATE users SET user_code=?"), anyString(), eq(1L))).thenReturn(1);
        when(jdbcTemplate.update(contains("UPDATE users SET user_code=?"), anyString(), eq(2L))).thenReturn(1);

        healing.run(new org.springframework.boot.DefaultApplicationArguments());

        ArgumentCaptor<String> codeCaptor = ArgumentCaptor.forClass(String.class);
        verify(jdbcTemplate, atLeastOnce()).update(contains("UPDATE users SET user_code=?"), codeCaptor.capture(), eq(1L));
        verify(jdbcTemplate, atLeastOnce()).update(contains("UPDATE users SET user_code=?"), codeCaptor.capture(), eq(2L));

        List<String> assigned = codeCaptor.getAllValues();
        assertEquals(2, assigned.size());
        for (String code : assigned) {
            assertTrue(code.matches("\\d{5}"), "靓号应为 5 位数字，实际: " + code);
            assertNotEquals("99999", code, "99999 保留给管理员");
            assertNotEquals("00001", code, "补号不得与现有账号冲突");
        }
    }

    @Test
    void run_shouldNeverChangeExistingCodes() {
        when(jdbcTemplate.queryForList(anyString(), eq(String.class))).thenReturn(List.of("00001"));
        when(jdbcTemplate.queryForList(sql(s -> s.contains("user_code = '99999'") && s.contains("<> 'admin'")), eq(Long.class))).thenReturn(List.of());
        when(jdbcTemplate.queryForList(sql(s -> s.contains("user_code = '99999'") && s.contains("= 'admin' ORDER BY id LIMIT 1")), eq(Long.class))).thenReturn(List.of());
        when(jdbcTemplate.queryForList(sql(s -> !s.contains("user_code = '99999'") && s.contains("'admin' ORDER BY id")), eq(Long.class))).thenReturn(List.of());
        when(jdbcTemplate.queryForList(sql(s -> s.contains("user_code IS NULL OR user_code = ''")), eq(Long.class))).thenReturn(List.of());

        healing.run(new org.springframework.boot.DefaultApplicationArguments());

        verify(jdbcTemplate, never()).update(anyString(), anyString(), eq(1L));
        verify(jdbcTemplate, never()).update(eq("UPDATE users SET user_code='99999' WHERE id=?"), eq(7L));
    }
}
