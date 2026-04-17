package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.core.DefaultSecurityPolicyService;
import io.github.jho951.platform.security.ip.DefaultBoundaryIpPolicyProvider;
import io.github.jho951.platform.security.policy.DefaultAuthenticationModeResolver;
import io.github.jho951.platform.security.policy.DefaultClientTypeResolver;
import io.github.jho951.platform.security.policy.DefaultPlatformPrincipalFactory;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.ratelimit.DefaultBoundaryRateLimitPolicyProvider;
import io.github.jho951.platform.security.ratelimit.DefaultRateLimitKeyResolver;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class PlatformSecurityAcceptanceTest {
    @Test
    void publicBoundaryAllowsWithoutAuthentication() {
        PlatformSecurityProperties properties = baseProperties();
        SecurityIngressAdapter adapter = adapter(properties);

        SecurityVerdict verdict = adapter.evaluate(
                newRequest("/health", "127.0.0.1", Map.of()),
                new SecurityContext(false, null, Set.of(), Map.of())
        );

        assertEquals(true, verdict.allowed());
    }

    @Test
    void protectedBoundaryRequiresAuthentication() {
        PlatformSecurityProperties properties = baseProperties();
        SecurityIngressAdapter adapter = adapter(properties);

        SecurityFailureResponse response = adapter.evaluateFailureResponse(
                newRequest("/api/orders", "127.0.0.1", Map.of()),
                new SecurityContext(false, null, Set.of(), Map.of())
        );

        assertEquals(401, response.status());
    }

    @Test
    void adminBoundaryRejectsDisallowedIp() {
        PlatformSecurityProperties properties = baseProperties();
        properties.getIpGuard().setAdminAllowCidrs(List.of("10.0.0.0/8"));
        SecurityIngressAdapter adapter = adapter(properties);

        SecurityFailureResponse response = adapter.evaluateFailureResponse(
                newRequest("/admin/users", "192.168.1.10", Map.of()),
                new SecurityContext(true, "admin-1", Set.of("ADMIN"), Map.of())
        );

        assertEquals(403, response.status(), () -> "status=" + response.status() + ", code=" + response.code() + ", message=" + response.message());
    }

    @Test
    void anonymousRequestsAreRateLimited() {
        PlatformSecurityProperties properties = baseProperties();
        properties.getAuth().setDefaultMode(io.github.jho951.platform.security.policy.AuthMode.NONE);
        properties.getRateLimit().getAnonymous().setRequests(1L);
        properties.getRateLimit().getAnonymous().setWindowSeconds(60L);
        SecurityIngressAdapter adapter = adapter(properties);
        SecurityContext anonymous = new SecurityContext(false, null, Set.of(), Map.of());

        SecurityFailureResponse first = adapter.evaluateFailureResponse(
                newRequest("/api/orders", "127.0.0.1", Map.of()),
                anonymous
        );
        SecurityFailureResponse second = adapter.evaluateFailureResponse(
                newRequest("/api/orders", "127.0.0.1", Map.of()),
                anonymous
        );

        assertEquals(200, first.status(), () -> "status=" + first.status() + ", code=" + first.code() + ", message=" + first.message());
        assertEquals(429, second.status(), () -> "status=" + second.status() + ", code=" + second.code() + ", message=" + second.message());
    }

    @Test
    void publicLoginRouteCanBeRateLimited() {
        PlatformSecurityProperties properties = baseProperties();
        properties.getBoundary().setPublicPaths(List.of("/health", "/auth/login", "/auth/refresh", "/auth/sso/start"));
        PlatformSecurityProperties.RouteRateLimitPolicyProperties login = new PlatformSecurityProperties.RouteRateLimitPolicyProperties();
        login.setName("login");
        login.setPatterns(List.of("/auth/login", "/auth/refresh", "/auth/sso/start"));
        login.setRequests(1L);
        login.setWindowSeconds(60L);
        properties.getRateLimit().setRoutes(List.of(login));
        SecurityIngressAdapter adapter = adapter(properties);
        SecurityContext anonymous = new SecurityContext(false, null, Set.of(), Map.of());

        SecurityFailureResponse first = adapter.evaluateFailureResponse(
                newRequest("/auth/login", "127.0.0.1", Map.of()),
                anonymous
        );
        SecurityFailureResponse second = adapter.evaluateFailureResponse(
                newRequest("/auth/login", "127.0.0.1", Map.of()),
                anonymous
        );

        assertEquals(200, first.status());
        assertEquals(429, second.status());
    }

    @Test
    void trustProxyFalseIgnoresForwardedForHeader() {
        PlatformSecurityProperties properties = baseProperties();
        properties.getIpGuard().setTrustProxy(false);
        SecurityIngressRequestFactory factory = requestFactory(properties);

        SecurityRequest request = factory.fromServlet(mockRequest("/api/orders", "10.0.0.10", Map.of("X-Forwarded-For", "1.2.3.4")), java.time.Clock.systemUTC());

        assertEquals("10.0.0.10", request.clientIp());
    }

    @Test
    void browserSessionIsRejectedWhenDisabled() {
        PlatformSecurityProperties properties = baseProperties();
        properties.getAuth().setAllowSessionForBrowser(false);
        SecurityIngressAdapter adapter = adapter(properties);

        SecurityFailureResponse response = adapter.evaluateFailureResponse(
                newRequest("/api/orders", "127.0.0.1", Map.of("auth.sessionId", "session-1")),
                new SecurityContext(false, null, Set.of(), Map.of())
        );

        assertEquals(401, response.status());
    }

    @Test
    void bearerAuthenticationIsRejectedWhenDisabled() {
        PlatformSecurityProperties properties = baseProperties();
        properties.getAuth().setAllowBearerForApi(false);
        SecurityIngressAdapter adapter = adapter(properties);

        SecurityFailureResponse response = adapter.evaluateFailureResponse(
                newRequest("/api/orders", "127.0.0.1", Map.of("auth.accessToken", "token-1")),
                new SecurityContext(false, null, Set.of(), Map.of())
        );

        assertEquals(401, response.status());
    }

    @Test
    void internalBoundaryUsesInternalQuota() {
        PlatformSecurityProperties properties = baseProperties();
        properties.getIpGuard().getInternal().setRules(List.of("127.0.0.1/32"));
        properties.getRateLimit().getInternal().setRequests(1L);
        properties.getRateLimit().getInternal().setWindowSeconds(60L);
        SecurityIngressAdapter adapter = adapter(properties);
        SecurityContext internalContext = new SecurityContext(true, "internal-service", Set.of(), Map.of());

        SecurityFailureResponse first = adapter.evaluateFailureResponse(
                newRequest("/internal/sync", "127.0.0.1", Map.of("auth.accessToken", "internal-token")),
                internalContext
        );
        SecurityFailureResponse second = adapter.evaluateFailureResponse(
                newRequest("/internal/sync", "127.0.0.1", Map.of("auth.accessToken", "internal-token")),
                internalContext
        );

        assertEquals(200, first.status());
        assertEquals(429, second.status());
    }

    @Test
    void spoofedSecurityHeadersAreIgnored() {
        PlatformSecurityProperties properties = baseProperties();
        SecurityIngressRequestFactory factory = requestFactory(properties);

        SecurityRequest request = factory.fromServlet(
                mockRequest("/api/orders", "127.0.0.1", Map.of(
                        "X-Security-Principal", "evil",
                        "X-Security-Auth-Mode", "JWT",
                        "X-Auth-Roles", "ADMIN",
                        "X-Auth-Session-Id", "session-1"
                )),
                java.time.Clock.systemUTC()
        );

        assertNull(request.attributes().get("X-Security-Principal"));
        assertNull(request.attributes().get("X-Security-Auth-Mode"));
        assertNull(request.attributes().get("X-Auth-Roles"));
        assertEquals("session-1", request.attributes().get("auth.sessionId"));
    }

    private PlatformSecurityProperties baseProperties() {
        PlatformSecurityProperties properties = new PlatformSecurityProperties();
        properties.getBoundary().setPublicPaths(List.of("/health"));
        properties.getBoundary().setProtectedPaths(List.of("/api/**"));
        properties.getBoundary().setAdminPaths(List.of("/admin/**"));
        properties.getBoundary().setInternalPaths(List.of("/internal/**"));
        properties.getRateLimit().getAnonymous().setRequests(1L);
        properties.getRateLimit().getAnonymous().setWindowSeconds(60L);
        properties.getRateLimit().getAuthenticated().setRequests(100L);
        properties.getRateLimit().getAuthenticated().setWindowSeconds(60L);
        properties.getRateLimit().getInternal().setRequests(1000L);
        properties.getRateLimit().getInternal().setWindowSeconds(60L);
        return properties;
    }

    private SecurityIngressAdapter adapter(PlatformSecurityProperties properties) {
        var boundaryResolver = new PathPatternSecurityBoundaryResolver(
                properties.getBoundary().getPublicPaths(),
                properties.getBoundary().getProtectedPaths(),
                properties.getBoundary().getAdminPaths(),
                properties.getBoundary().getInternalPaths()
        );
        var service = new DefaultSecurityPolicyService(
                boundaryResolver,
                new DefaultClientTypeResolver(),
                new DefaultAuthenticationModeResolver(properties.getAuth()),
                new DefaultBoundaryIpPolicyProvider(properties.getIpGuard()),
                new DefaultBoundaryRateLimitPolicyProvider(properties.getRateLimit(), new DefaultRateLimitKeyResolver()),
                new DefaultPlatformPrincipalFactory()
        );
        return new SecurityIngressAdapter(service, boundaryResolver);
    }

    private SecurityIngressRequestFactory requestFactory(PlatformSecurityProperties properties) {
        return new SecurityIngressRequestFactory(
                new DefaultClientIpResolver(properties.getIpGuard()),
                new SecurityIdentityScrubber()
        );
    }

    private org.springframework.mock.web.MockHttpServletRequest mockRequest(
            String path,
            String remoteAddr,
            Map<String, String> headers
    ) {
        org.springframework.mock.web.MockHttpServletRequest request = new org.springframework.mock.web.MockHttpServletRequest("GET", path);
        request.setRemoteAddr(remoteAddr);
        headers.forEach(request::addHeader);
        return request;
    }

    private io.github.jho951.platform.security.api.SecurityRequest newRequest(
            String path,
            String clientIp,
            Map<String, String> attributes
    ) {
        return new io.github.jho951.platform.security.api.SecurityRequest(
                null,
                clientIp,
                path,
                "GET",
                attributes,
                Instant.parse("2026-01-01T00:00:00Z")
        );
    }
}
