package com.jdy.cloud.config;

import com.jdy.cloud.model.User;
import com.jdy.cloud.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** 首个管理员引导：只建号、不夺号、不覆盖已有管理员。 */
@ExtendWith(MockitoExtension.class)
class AdminBootstrapTest {

    @Mock
    private UserRepository userRepository;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(4);

    private static final String USERNAME = "siteadmin";
    private static final String PASSWORD = "Str0ng-Passw0rd";
    private static final String EMAIL = "siteadmin@example.com";

    private AdminBootstrap bootstrap;

    @BeforeEach
    void setUp() {
        bootstrap = new AdminBootstrap(userRepository, passwordEncoder, USERNAME, PASSWORD, EMAIL);
    }

    private void run() {
        bootstrap.run(new org.springframework.boot.DefaultApplicationArguments());
    }

    @Test
    void createsAdminWhenNoneExists() {
        when(userRepository.countByRole("admin")).thenReturn(0L);
        when(userRepository.existsByUsername(USERNAME)).thenReturn(false);
        when(userRepository.existsByEmail(EMAIL)).thenReturn(false);

        run();

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        User saved = captor.getValue();

        assertEquals(USERNAME, saved.getUsername());
        assertEquals(EMAIL, saved.getEmail());
        assertEquals("admin", saved.getRole());
        assertEquals("active", saved.getUserStatus());
        assertEquals("verified", saved.getVerificationStatus());
        assertTrue(saved.getIsOfficial());
        assertNull(saved.getId(), "应由数据库分配主键");
        assertNotEquals(PASSWORD, saved.getPassword(), "密码不得以明文落库");
        assertTrue(passwordEncoder.matches(PASSWORD, saved.getPassword()), "落库的哈希必须能校验原密码");
    }

    @Test
    void neverTouchesDatabaseWhenAdminAlreadyExists() {
        when(userRepository.countByRole("admin")).thenReturn(1L);

        run();

        verify(userRepository, never()).save(any(User.class));
        verify(userRepository, never()).existsByUsername(anyString());
    }

    @Test
    void skipsWhenPasswordMissing() {
        when(userRepository.countByRole("admin")).thenReturn(0L);

        new AdminBootstrap(userRepository, passwordEncoder, USERNAME, "", EMAIL).run(
                new org.springframework.boot.DefaultApplicationArguments());

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void skipsWhenPasswordTooShort() {
        when(userRepository.countByRole("admin")).thenReturn(0L);

        new AdminBootstrap(userRepository, passwordEncoder, USERNAME, "short", EMAIL).run(
                new org.springframework.boot.DefaultApplicationArguments());

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void neverPromotesAnExistingAccount() {
        when(userRepository.countByRole("admin")).thenReturn(0L);
        when(userRepository.existsByUsername(USERNAME)).thenReturn(true);

        run();

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void skipsWhenEmailAlreadyUsed() {
        when(userRepository.countByRole("admin")).thenReturn(0L);
        when(userRepository.existsByUsername(USERNAME)).thenReturn(false);
        when(userRepository.existsByEmail(EMAIL)).thenReturn(true);

        run();

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void fallsBackToPlaceholderEmailWhenNotConfigured() {
        when(userRepository.countByRole("admin")).thenReturn(0L);
        when(userRepository.existsByUsername(USERNAME)).thenReturn(false);
        when(userRepository.existsByEmail(USERNAME + "@localhost")).thenReturn(false);

        new AdminBootstrap(userRepository, passwordEncoder, USERNAME, PASSWORD, "").run(
                new org.springframework.boot.DefaultApplicationArguments());

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        assertEquals(USERNAME + "@localhost", captor.getValue().getEmail());
    }

    @Test
    void neverFailsStartupWhenRepositoryIsBroken() {
        when(userRepository.countByRole("admin")).thenThrow(new IllegalStateException("db down"));

        run();

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void isIdempotentAcrossRestarts() {
        when(userRepository.countByRole("admin")).thenReturn(0L, 1L);
        when(userRepository.existsByUsername(USERNAME)).thenReturn(false);
        when(userRepository.existsByEmail(EMAIL)).thenReturn(false);

        run();
        run();

        verify(userRepository).save(any(User.class));
    }
}
