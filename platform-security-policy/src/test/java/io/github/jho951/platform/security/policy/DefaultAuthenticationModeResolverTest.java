package io.github.jho951.platform.security.policy;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityRequest;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DefaultAuthenticationModeResolverTest {
    @Test
    void browserSessionRequiresPropertyToggle() {
        PlatformSecurityProperties.AuthProperties properties = new PlatformSecurityProperties.AuthProperties();
        properties.setAllowSessionForBrowser(false);
        DefaultAuthenticationModeResolver resolver = new DefaultAuthenticationModeResolver(properties);

        AuthMode mode = resolver.resolve(
                request(Map.of("auth.sessionId", "session-1")),
                new SecurityContext(false, null, Set.of(), Map.of()),
                new SecurityBoundary(SecurityBoundaryType.PROTECTED, java.util.List.of("/api/**")),
                ClientType.BROWSER
        );

        assertEquals(AuthMode.HYBRID, mode);
    }

    @Test
    void externalApiBearerRequiresPropertyToggle() {
        PlatformSecurityProperties.AuthProperties properties = new PlatformSecurityProperties.AuthProperties();
        properties.setAllowBearerForApi(false);
        DefaultAuthenticationModeResolver resolver = new DefaultAuthenticationModeResolver(properties);

        AuthMode mode = resolver.resolve(
                request(Map.of("auth.accessToken", "token-1")),
                new SecurityContext(false, null, Set.of(), Map.of()),
                new SecurityBoundary(SecurityBoundaryType.PROTECTED, java.util.List.of("/api/**")),
                ClientType.EXTERNAL_API
        );

        assertEquals(AuthMode.HYBRID, mode);
    }

    @Test
    void internalBoundaryRequiresInternalTokenToggle() {
        PlatformSecurityProperties.AuthProperties properties = new PlatformSecurityProperties.AuthProperties();
        properties.setInternalTokenEnabled(false);
        DefaultAuthenticationModeResolver resolver = new DefaultAuthenticationModeResolver(properties);

        AuthMode mode = resolver.resolve(
                request(Map.of()),
                new SecurityContext(true, "internal-service", Set.of(), Map.of()),
                new SecurityBoundary(SecurityBoundaryType.INTERNAL, java.util.List.of("/internal/**")),
                ClientType.INTERNAL_SERVICE
        );

        assertEquals(AuthMode.HYBRID, mode);
    }

    @Test
    void apiKeyCredentialSelectsApiKeyMode() {
        DefaultAuthenticationModeResolver resolver = new DefaultAuthenticationModeResolver(new PlatformSecurityProperties.AuthProperties());

        AuthMode mode = resolver.resolve(
                request(Map.of("auth.apiKeyId", "key-1", "auth.apiKeySecret", "secret-1")),
                new SecurityContext(false, null, Set.of(), Map.of()),
                new SecurityBoundary(SecurityBoundaryType.PROTECTED, java.util.List.of("/api/**")),
                ClientType.EXTERNAL_API
        );

        assertEquals(AuthMode.API_KEY, mode);
    }

    @Test
    void serviceAccountCredentialSelectsServiceAccountModeOnInternalBoundary() {
        DefaultAuthenticationModeResolver resolver = new DefaultAuthenticationModeResolver(new PlatformSecurityProperties.AuthProperties());

        AuthMode mode = resolver.resolve(
                request(Map.of("auth.serviceAccountId", "svc-1", "auth.serviceAccountSecret", "secret-1")),
                new SecurityContext(false, null, Set.of(), Map.of()),
                new SecurityBoundary(SecurityBoundaryType.INTERNAL, java.util.List.of("/internal/**")),
                ClientType.INTERNAL_SERVICE
        );

        assertEquals(AuthMode.SERVICE_ACCOUNT, mode);
    }

    private SecurityRequest request(Map<String, String> attributes) {
        return new SecurityRequest(null, "127.0.0.1", "/api/orders", "GET", attributes, Instant.parse("2026-01-01T00:00:00Z"));
    }
}
