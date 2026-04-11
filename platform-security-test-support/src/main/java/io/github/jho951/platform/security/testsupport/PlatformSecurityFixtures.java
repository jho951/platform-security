package io.github.jho951.platform.security.testsupport;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.policy.AuthMode;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

public final class PlatformSecurityFixtures {
    private PlatformSecurityFixtures() {}

    public static SecurityRequest sampleRequest() {
        return new SecurityRequest(
                "user-1",
                "127.0.0.1",
                "/api/demo",
                "read",
                Map.of("source", "test"),
                Instant.parse("2026-01-01T00:00:00Z")
        );
    }

    public static SecurityContext authenticatedContext() {
        return new SecurityContext(true, "user-1", Set.of("USER"), Map.of());
    }

    public static PlatformSecurityProperties gatewayServerProperties() {
        PlatformSecurityProperties properties = baseProperties();
        properties.getBoundary().setPublicPaths(java.util.List.of("/health", "/auth/login", "/auth/refresh"));
        properties.getBoundary().setProtectedPaths(java.util.List.of("/api/**"));
        properties.getBoundary().setAdminPaths(java.util.List.of("/admin/**"));
        properties.getBoundary().setInternalPaths(java.util.List.of("/internal/**"));

        properties.getAuth().setDefaultMode(AuthMode.HYBRID);
        properties.getAuth().setAllowSessionForBrowser(true);
        properties.getAuth().setAllowBearerForApi(true);
        properties.getAuth().setInternalTokenEnabled(true);

        properties.getIpGuard().setEnabled(true);
        properties.getIpGuard().setTrustProxy(true);
        properties.getIpGuard().setAdminAllowCidrs(java.util.List.of("10.0.0.0/8"));
        properties.getIpGuard().setInternalAllowCidrs(java.util.List.of("172.16.0.0/12"));

        properties.getRateLimit().getAnonymous().setRequests(60L);
        properties.getRateLimit().getAnonymous().setWindowSeconds(60L);
        properties.getRateLimit().getAuthenticated().setRequests(300L);
        properties.getRateLimit().getAuthenticated().setWindowSeconds(60L);
        properties.getRateLimit().getInternal().setRequests(1000L);
        properties.getRateLimit().getInternal().setWindowSeconds(60L);
        return properties;
    }

    public static PlatformSecurityProperties authServerProperties() {
        PlatformSecurityProperties properties = baseProperties();
        properties.getBoundary().setPublicPaths(java.util.List.of("/health", "/auth/login", "/auth/refresh", "/auth/logout"));
        properties.getBoundary().setProtectedPaths(java.util.List.of("/api/**"));
        properties.getBoundary().setAdminPaths(java.util.List.of("/admin/**"));
        properties.getBoundary().setInternalPaths(java.util.List.of("/internal/**"));

        properties.getAuth().setDefaultMode(AuthMode.HYBRID);
        properties.getAuth().setAllowSessionForBrowser(true);
        properties.getAuth().setAllowBearerForApi(true);
        properties.getAuth().setInternalTokenEnabled(true);
        properties.getAuth().setJwtSecret("platform-security-auth-server-secret-platform-security-auth-server-secret");

        properties.getIpGuard().setEnabled(true);
        properties.getIpGuard().setTrustProxy(true);
        properties.getIpGuard().setAdminAllowCidrs(java.util.List.of("10.0.0.0/8"));
        properties.getIpGuard().setInternalAllowCidrs(java.util.List.of("172.16.0.0/12"));

        properties.getRateLimit().getAnonymous().setRequests(30L);
        properties.getRateLimit().getAnonymous().setWindowSeconds(60L);
        properties.getRateLimit().getAuthenticated().setRequests(200L);
        properties.getRateLimit().getAuthenticated().setWindowSeconds(60L);
        properties.getRateLimit().getInternal().setRequests(1000L);
        properties.getRateLimit().getInternal().setWindowSeconds(60L);
        return properties;
    }

    private static PlatformSecurityProperties baseProperties() {
        PlatformSecurityProperties properties = new PlatformSecurityProperties();
        properties.setEnabled(true);
        return properties;
    }
}
