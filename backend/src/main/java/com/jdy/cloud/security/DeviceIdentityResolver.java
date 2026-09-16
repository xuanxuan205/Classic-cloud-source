package com.jdy.cloud.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

/**
 * IronWall v1.29.0: 设备身份统一解析。
 * fingerprint：浏览器硬件指纹（X-IronWall-FP 头，回退 iw_fp Cookie）；
 * deviceId：服务端签名设备ID（iw_did Cookie，仅接受通过签名校验的值）；
 * signature：指纹绑定签名（iw_fp_sig Cookie），用于校验指纹是否属于该设备。
 */
@Component
public class DeviceIdentityResolver {

    public static final String FP_HEADER = "X-IronWall-FP";
    public static final String FP_COOKIE = "iw_fp";
    public static final String DID_COOKIE = "iw_did";
    public static final String SIG_COOKIE = "iw_fp_sig";

    private final AttackGuardService attackGuardService;

    public DeviceIdentityResolver(AttackGuardService attackGuardService) {
        this.attackGuardService = attackGuardService;
    }

    public Identity resolve(HttpServletRequest request) {
        String fingerprint = headerOrCookie(request, FP_HEADER, FP_COOKIE);
        String did = cookie(request, DID_COOKIE);
        if (did != null && (attackGuardService == null || !attackGuardService.isValidDeviceId(did))) {
            did = null;
        }
        String signature = cookie(request, SIG_COOKIE);
        return new Identity(fingerprint, did, signature);
    }

    private String headerOrCookie(HttpServletRequest request, String headerName, String cookieName) {
        String header = request.getHeader(headerName);
        if (header != null && !header.isBlank()) {
            return header.trim();
        }
        return cookie(request, cookieName);
    }

    private String cookie(HttpServletRequest request, String name) {
        jakarta.servlet.http.Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        for (jakarta.servlet.http.Cookie cookie : cookies) {
            if (name.equals(cookie.getName()) && cookie.getValue() != null && !cookie.getValue().isBlank()) {
                return cookie.getValue().trim();
            }
        }
        return null;
    }

    public record Identity(String fingerprint, String deviceId, String signature) {
    }
}
