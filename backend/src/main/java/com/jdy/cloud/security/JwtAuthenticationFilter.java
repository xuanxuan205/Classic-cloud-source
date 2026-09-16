package com.jdy.cloud.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jdy.cloud.util.ClientIpUtils;
import com.jdy.cloud.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IronWall v1.11: 封禁账号实时吊销。
 * 管理员封禁用户后，其已签发的 JWT 在缓存 TTL 内（默认 60 秒）全部失效并返回 403，
 * 不再需要等到令牌自然过期。
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final long BANNED_CACHE_TTL_MS = 60_000L;

    private final JwtTokenProvider jwtTokenProvider;
    private final TokenVersionService tokenVersionService;
    private final UserRepository userRepository;
    private final TrapService trapService;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<Long, CacheEntry> bannedCache = new ConcurrentHashMap<>();

    private static final class CacheEntry {
        final boolean banned;
        final long expiresAt;
        CacheEntry(boolean banned, long expiresAt) {
            this.banned = banned;
            this.expiresAt = expiresAt;
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String token = extractToken(request);

        if (StringUtils.hasText(token) && jwtTokenProvider.validateToken(token)) {
            // IronWall v1.28.1: 两步验证中间令牌只服务于 /api/auth/2fa/login，禁止进入业务鉴权链
            // （fail-closed：伪造角色或缺失角色的令牌一律 401，杜绝 ROLE_NULL 越权与空指针）
            if (jwtTokenProvider.isTwoFactorToken(token) || jwtTokenProvider.getRoleFromToken(token) == null) {
                log.warn("[IronWall] non-session token rejected: path={}", request.getRequestURI());
                writeUnauthorizedResponse(response);
                return;
            }
            Long userId = jwtTokenProvider.getUserIdFromToken(token);
            String username = jwtTokenProvider.getUsernameFromToken(token);
            String role = jwtTokenProvider.getRoleFromToken(token);

            // IronWall v1.20: 令牌版本号校验。改密/重置/封禁后旧 JWT 立即 401。
            int tokenVersion = jwtTokenProvider.getTokenVersionFromToken(token);
            if (!tokenVersionService.matches(userId, tokenVersion)) {
                log.warn("[IronWall] token version mismatch, revoking: userId={} path={}", userId, request.getRequestURI());
                writeUnauthorizedResponse(response);
                return;
            }
            UserState userState = resolveUserState(userId);
            if (userState == UserState.GONE) {
                // IronWall v1.21: 幽灵令牌（已注销账号）回放 = 会话层对抗，投入 L5 黑洞陷阱
                trapService.trap(ClientIpUtils.getClientIp(request), 5, "幽灵令牌回放", request.getRequestURI(), request.getHeader("User-Agent"), request.getMethod(), false);
                log.warn("[IronWall] token of removed user rejected: userId={} path={}", userId, request.getRequestURI());
                writeUnauthorizedResponse(response);
                return;
            }
            if (userState == UserState.BANNED) {
                // IronWall v1.21: 封禁账号令牌回放 = 会话层对抗，投入 L5 黑洞陷阱
                trapService.trap(ClientIpUtils.getClientIp(request), 5, "封禁账号令牌回放", request.getRequestURI(), request.getHeader("User-Agent"), request.getMethod(), false);
                log.warn("[IronWall] banned account token rejected: userId={} path={}", userId, request.getRequestURI());
                writeBannedResponse(response);
                return;
            }

            List<SimpleGrantedAuthority> authorities = List.of(
                    new SimpleGrantedAuthority("ROLE_" + role.toUpperCase())
            );

            UserPrincipal principal = new UserPrincipal(userId, username, role);
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(principal, null, authorities);
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        chain.doFilter(request, response);
    }

    private enum UserState { OK, BANNED, GONE }

    private UserState resolveUserState(Long userId) {
        if (userId == null) return UserState.OK;
        long now = System.currentTimeMillis();
        CacheEntry cached = bannedCache.get(userId);
        if (cached != null && cached.expiresAt > now) {
            return cached.banned ? UserState.BANNED : UserState.OK;
        }
        UserState state;
        try {
            state = userRepository.findById(userId)
                    .map(u -> "banned".equalsIgnoreCase(u.getUserStatus()) ? UserState.BANNED : UserState.OK)
                    // IronWall v1.20: 用户已注销/删除的令牌 fail-closed 401，不允许幽灵会话
                    .orElse(UserState.GONE);
        } catch (Exception e) {
            // fail-open: 数据库短暂异常时交由下游接口处理，不让过滤器把流量变 500
            log.error("[IronWall] banned check failed, fail-open: {}", e.getMessage());
            return UserState.OK;
        }
        bannedCache.put(userId, new CacheEntry(state == UserState.BANNED, now + BANNED_CACHE_TTL_MS));
        return state;
    }

    private void writeUnauthorizedResponse(HttpServletResponse response) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(
                Map.of("success", false,
                       "code", 401,
                       "message", "身份状态已变更，请重新登录")
        ));
    }

    private void writeBannedResponse(HttpServletResponse response) throws IOException {
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(
                Map.of("success", false,
                       "code", 1012,
                       "message", "\u8d26\u53f7\u5df2\u88ab\u5c01\u7981\uff0c\u8bf7\u8054\u7cfb\u7ba1\u7406\u5458",
                       "engine", AttackGuardService.ENGINE_NAME)
        ));
    }

    private String extractToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
