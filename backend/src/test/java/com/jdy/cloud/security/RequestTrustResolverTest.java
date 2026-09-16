package com.jdy.cloud.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * IronWall v1.15: trust-level resolution contract tests.
 * Whitelisted IP > valid JWT (admin/user) > anonymous.
 */
@ExtendWith(MockitoExtension.class)
class RequestTrustResolverTest {

    @Mock private JwtTokenProvider jwtTokenProvider;

    private RequestTrustResolver resolver;

    @BeforeEach
    void setUp() {
        resolver = new RequestTrustResolver(jwtTokenProvider);
        resolver.setAdminIpWhitelist("1.2.3.4, 5.6.7.8");
    }

    private MockHttpServletRequest requestWithToken(String token) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/files/list");
        if (token != null) {
            request.addHeader("Authorization", "Bearer " + token);
        }
        return request;
    }

    @Test
    void whitelistedIpShouldResolveFirstEvenWithNoToken() {
        assertEquals(RequestTrustResolver.Level.WHITELISTED,
                resolver.resolve(requestWithToken(null), "1.2.3.4"));
        assertEquals(RequestTrustResolver.Level.WHITELISTED,
                resolver.resolve(requestWithToken("garbage"), "5.6.7.8"));
        verifyNoInteractions(jwtTokenProvider);
    }

    @Test
    void adminTokenShouldResolveToAdmin() {
        MockHttpServletRequest request = requestWithToken("admin-token");
        when(jwtTokenProvider.validateToken("admin-token")).thenReturn(true);
        when(jwtTokenProvider.getRoleFromToken("admin-token")).thenReturn("admin");

        assertEquals(RequestTrustResolver.Level.ADMIN, resolver.resolve(request, "9.9.9.9"));
    }

    @Test
    void adminRoleShouldBeCaseInsensitive() {
        MockHttpServletRequest request = requestWithToken("admin-token");
        when(jwtTokenProvider.validateToken("admin-token")).thenReturn(true);
        when(jwtTokenProvider.getRoleFromToken("admin-token")).thenReturn("ADMIN");

        assertEquals(RequestTrustResolver.Level.ADMIN, resolver.resolve(request, "9.9.9.9"));
    }

    @Test
    void userTokenShouldResolveToAuthenticated() {
        MockHttpServletRequest request = requestWithToken("user-token");
        when(jwtTokenProvider.validateToken("user-token")).thenReturn(true);
        when(jwtTokenProvider.getRoleFromToken("user-token")).thenReturn("user");

        assertEquals(RequestTrustResolver.Level.AUTHENTICATED, resolver.resolve(request, "9.9.9.9"));
    }

    @Test
    void invalidTokenShouldResolveToAnonymous() {
        MockHttpServletRequest request = requestWithToken("expired-token");
        when(jwtTokenProvider.validateToken("expired-token")).thenReturn(false);

        assertEquals(RequestTrustResolver.Level.ANONYMOUS, resolver.resolve(request, "9.9.9.9"));
    }

    @Test
    void missingTokenShouldResolveToAnonymous() {
        assertEquals(RequestTrustResolver.Level.ANONYMOUS,
                resolver.resolve(requestWithToken(null), "9.9.9.9"));
    }

    @Test
    void emptyWhitelistShouldNotWhitelistAnything() {
        resolver.setAdminIpWhitelist("");
        MockHttpServletRequest request = requestWithToken("user-token");
        when(jwtTokenProvider.validateToken("user-token")).thenReturn(true);
        when(jwtTokenProvider.getRoleFromToken("user-token")).thenReturn("user");

        assertEquals(RequestTrustResolver.Level.AUTHENTICATED, resolver.resolve(request, "1.2.3.4"));
    }

    @Test
    void loopbackShouldAlwaysResolveToWhitelistedR54K() {
        assertEquals(RequestTrustResolver.Level.WHITELISTED,
                resolver.resolve(requestWithToken(null), "127.0.0.1"));
        assertEquals(RequestTrustResolver.Level.WHITELISTED,
                resolver.resolve(requestWithToken("garbage"), "127.0.0.2"));
        assertEquals(RequestTrustResolver.Level.WHITELISTED,
                resolver.resolve(requestWithToken(null), "::1"));
        assertTrue(resolver.isWhitelisted("127.8.8.8"));
    }

    @Test
    void userIdShouldBeExtractedFromValidToken() {
        MockHttpServletRequest request = requestWithToken("user-token");
        when(jwtTokenProvider.validateToken("user-token")).thenReturn(true);
        when(jwtTokenProvider.getUserIdFromToken("user-token")).thenReturn(42L);

        assertEquals(42L, resolver.userId(request));
    }

    @Test
    void userIdShouldBeNullForAnonymousRequest() {
        assertNull(resolver.userId(requestWithToken(null)));
    }
}
