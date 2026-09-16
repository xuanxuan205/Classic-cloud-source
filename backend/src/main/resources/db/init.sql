-- ============================================
-- JDY Cloud - 数据库初始化脚本
-- ============================================

CREATE DATABASE IF NOT EXISTS jdy_cloud
    DEFAULT CHARACTER SET utf8mb4
    DEFAULT COLLATE utf8mb4_unicode_ci;
USE jdy_cloud;

-- ============================================
-- 用户表
-- ============================================
CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(30) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    is_official BOOLEAN DEFAULT FALSE,
    user_status VARCHAR(20) DEFAULT 'active',
    verification_status VARCHAR(20) DEFAULT 'unverified',
    storage_used BIGINT DEFAULT 0,
    storage_limit BIGINT DEFAULT 1073741824,
    upload_limit INT DEFAULT 850,
    avatar VARCHAR(500) DEFAULT NULL COMMENT 'avatar-url',
    user_code VARCHAR(5) DEFAULT NULL COMMENT 'user-code',
    verification_badge VARCHAR(50) DEFAULT NULL COMMENT 'verification-badge',
    avatar_size BIGINT DEFAULT 0 COMMENT 'avatar-size',
    login_attempts INT DEFAULT 0,
    token_version INT DEFAULT 0 COMMENT 'token-version',  -- IronWall v1.20: 改密/封禁即吊销旧 JWT
    locked_until DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE INDEX idx_users_username (username),
    UNIQUE INDEX idx_users_email (email),
    UNIQUE INDEX idx_users_user_code (user_code),
    INDEX idx_users_role (role),
    INDEX idx_users_status (user_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- 文件表
-- ============================================
CREATE TABLE IF NOT EXISTS files (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    original_name VARCHAR(500) NOT NULL,
    file_size BIGINT DEFAULT 0,
    file_type VARCHAR(50),
    mime_type VARCHAR(100),
    file_hash VARCHAR(64),
    user_id BIGINT NOT NULL,
    folder_id BIGINT DEFAULT 0,
    is_shared INT DEFAULT 0,
    download_count INT DEFAULT 0,
    status INT DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_files_user_id (user_id),
    INDEX idx_files_folder_id (folder_id),
    INDEX idx_files_user_status (user_id, status),
    INDEX idx_files_created_at (created_at),
    INDEX idx_files_hash (file_hash),
    CONSTRAINT fk_files_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- 文件夹表
-- ============================================
CREATE TABLE IF NOT EXISTS folders (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    name VARCHAR(100) NOT NULL,
    parent_id BIGINT DEFAULT 0,
    status INT DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_folders_user_id (user_id),
    INDEX idx_folders_parent_id (parent_id),
    CONSTRAINT fk_folders_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- 分享表
-- ============================================
CREATE TABLE IF NOT EXISTS shares (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    share_type INT DEFAULT 1,
    file_id BIGINT,
    folder_id BIGINT,
    share_code VARCHAR(16) NOT NULL,
    password VARCHAR(100),
    description VARCHAR(500),
    download_limit INT DEFAULT 0,
    download_count INT DEFAULT 0,
    expire_time DATETIME,
    status INT DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX idx_shares_code (share_code),
    INDEX idx_shares_user_id (user_id),
    INDEX idx_shares_status (status),
    CONSTRAINT fk_shares_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- 公告表
-- ============================================
CREATE TABLE IF NOT EXISTS announcements (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    content TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'published',
    created_by BIGINT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_ann_status (status),
    CONSTRAINT fk_ann_user FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- 登录历史表
-- ============================================
CREATE TABLE IF NOT EXISTS login_history (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    ip VARCHAR(45) NOT NULL,
    device VARCHAR(500),
    status VARCHAR(20) DEFAULT 'success',
    time DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_lh_user_id (user_id),
    INDEX idx_lh_time (time),
    INDEX idx_lh_status (status),
    CONSTRAINT fk_lh_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- 管理员账号
-- 本脚本只建表，不写入任何账号。
-- 首个管理员由启动脚本里的 ADMIN_USERNAME / ADMIN_PASSWORD / ADMIN_EMAIL 创建：
-- 应用启动时若库中还没有管理员，会按该配置建号；已存在管理员则不做任何改动。
-- 请务必在首次登录后修改密码。
--
-- 想手工建号，可参考下面这段（password 必须是 BCrypt 哈希，不能填明文）：
-- INSERT INTO users (username, email, password, role, verification_status, is_official, user_status)
-- VALUES ('admin', 'admin@example.com', '<BCrypt 哈希>', 'admin', 'verified', TRUE, 'active');
--
-- 也可以先注册一个普通账号，再提权为管理员：
-- UPDATE users SET role='admin', is_official=TRUE WHERE username='你的账号';
-- ============================================


-- ============================================
-- 迁移: 头像字段 (如果列已存在会忽略错误)
-- ============================================
-- MySQL 不支持 ALTER TABLE ADD COLUMN IF NOT EXISTS
-- IronWall v1.10: legacy installs may lack these columns; the backend also self-heals them at startup (SchemaSelfHealing)
-- ALTER TABLE users ADD COLUMN avatar VARCHAR(500) DEFAULT NULL COMMENT 'avatar-url';
-- ALTER TABLE users ADD COLUMN user_code VARCHAR(5) DEFAULT NULL COMMENT 'user-code';
-- ALTER TABLE users ADD COLUMN verification_badge VARCHAR(50) DEFAULT NULL COMMENT 'verification-badge';
-- ============================================
-- 通知设置表
-- ============================================
CREATE TABLE IF NOT EXISTS notification_settings (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    email_notify TINYINT(1) DEFAULT 1,
    browser_notify TINYINT(1) DEFAULT 1,
    storage_alert TINYINT(1) DEFAULT 1,
    share_notify TINYINT(1) DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE INDEX idx_ns_user_id (user_id),
    CONSTRAINT fk_ns_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================
-- 系统配置表
-- ============================================
CREATE TABLE IF NOT EXISTS system_config (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) NOT NULL,
    config_value TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE INDEX idx_sc_key (config_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 默认系统配置
INSERT IGNORE INTO system_config (config_key, config_value) VALUES
('site_name', '经典云网盘'),
('site_description', '安全可靠的云存储服务'),
('allow_registration', 'true'),
('allow_all_file_types', 'false'),
('share_settings', '{"max_downloads": 100, "default_expire_days": 7, "require_password": false}'),
('disabled_notice', ''),
('system_info', '{"version": "1.0.0", "server_time": ""}');
