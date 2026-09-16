package com.jdy.cloud.config;

import com.jdy.cloud.model.User;
import com.jdy.cloud.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * 管理员账号引导。
 *
 * 规则：
 * 1) 库中已存在管理员时，本组件不做任何改动（重复启动结果一致，不会覆盖已修改的密码）。
 * 2) 未配置密码时不创建账号，仅在日志中给出配置方式。
 * 3) 配置了密码且库中无管理员时创建；用户名若已被普通账号占用则跳过并告警，
 * 绝不把已存在的账号静默提权为管理员。
 */
@Slf4j
@Component
@Order(-1)
public class AdminBootstrap implements ApplicationRunner {

    private static final String ROLE_ADMIN = "admin";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final String username;
    private final String password;
    private final String email;

    public AdminBootstrap(UserRepository userRepository,
                          PasswordEncoder passwordEncoder,
                          @Value("${app.admin.username:admin}") String username,
                          @Value("${app.admin.password:}") String password,
                          @Value("${app.admin.email:}") String email) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.username = username == null ? "" : username.trim();
        this.password = password == null ? "" : password;
        this.email = email == null ? "" : email.trim();
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            if (userRepository.countByRole(ROLE_ADMIN) > 0) {
                log.info("[IronWall] AdminBootstrap: admin account already present, skipped");
                return;
            }
            if (password.isBlank()) {
                log.warn("[IronWall] AdminBootstrap: no admin account found and ADMIN_PASSWORD is empty. "
                        + "Set ADMIN_PASSWORD (and optionally ADMIN_USERNAME / ADMIN_EMAIL) and restart, "
                        + "or create the first admin from the SQL in db/init.sql.");
                return;
            }
            if (username.isBlank()) {
                log.warn("[IronWall] AdminBootstrap: ADMIN_USERNAME is empty, skipped");
                return;
            }
            if (password.length() < 8) {
                log.warn("[IronWall] AdminBootstrap: ADMIN_PASSWORD is shorter than 8 characters, skipped. "
                        + "Use a stronger password and restart.");
                return;
            }
            if (userRepository.existsByUsername(username)) {
                log.warn("[IronWall] AdminBootstrap: username '{}' is already taken by a non-admin account, skipped. "
                        + "Pick another ADMIN_USERNAME or promote that account manually.", username);
                return;
            }

            String adminEmail = email.isBlank() ? username + "@localhost" : email;
            if (userRepository.existsByEmail(adminEmail)) {
                log.warn("[IronWall] AdminBootstrap: email '{}' is already in use, skipped. "
                        + "Set a different ADMIN_EMAIL and restart.", adminEmail);
                return;
            }

            User admin = new User();
            admin.setUsername(username);
            admin.setEmail(adminEmail);
            admin.setPassword(passwordEncoder.encode(password));
            admin.setRole(ROLE_ADMIN);
            admin.setIsOfficial(true);
            admin.setUserStatus("active");
            admin.setVerificationStatus("verified");
            admin.setStorageUsed(0L);
            admin.setStorageLimit(1073741824L);
            admin.setUploadLimit(850);
            admin.setLoginAttempts(0);
            admin.setTokenVersion(0);
            userRepository.save(admin);

            log.info("[IronWall] AdminBootstrap: admin account '{}' created. Change the password after the first login.",
                    username);
        } catch (Exception e) {
            log.warn("[IronWall] AdminBootstrap skipped: {}", e.getMessage());
        }
    }
}
