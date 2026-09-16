package com.jdy.cloud.dto;

import lombok.Data;

@Data
public class LoginResponse {
    private String token;
    // IronWall v1.28.0: 两步验证中间态（two_factor_required=true 时只返回 two_factor_token，不返回业务 token）
    private Boolean twoFactorRequired;
    private String twoFactorToken;
    private UserInfo user;
    private String expiresAt;

    @Data
    public static class UserInfo {
        private Long id;
        private String username;
        private String email;
        private String role;
        private boolean isOfficial;
        private String userStatus;
        private String verificationStatus;
        private Long storageUsed;
        private Long storageLimit;
        private Integer uploadLimit;
        private String createdAt;
        private String avatar;
        private String userCode;
        private String verificationBadge;
    }
}
