package io.github.jho951.platform.security.auth;

import io.github.jho951.platform.security.api.SecurityRequest;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultInternalServiceAuthenticationCapabilityTest {
    @Test
    void usesDedicatedInternalTokenWhenPresent() {
        AtomicReference<String> seenAccessToken = new AtomicReference<>();
        AtomicReference<String> seenSessionId = new AtomicReference<>();
        DefaultInternalServiceAuthenticationCapability capability = new DefaultInternalServiceAuthenticationCapability((accessToken, sessionId) -> {
            seenAccessToken.set(accessToken);
            seenSessionId.set(sessionId);
            return Optional.of(new PlatformAuthenticatedPrincipal("internal-service", java.util.Set.of("INTERNAL"), Map.of()));
        }, (principal, request) -> true);

        Optional<PlatformAuthenticatedPrincipal> principal = capability.authenticate(new SecurityRequest(
                null,
                "127.0.0.1",
                "/internal/sync",
                "POST",
                Map.of(
                        PlatformAuthenticationFacade.INTERNAL_TOKEN_ATTRIBUTE, "internal-token",
                        PlatformAuthenticationFacade.ACCESS_TOKEN_ATTRIBUTE, "bearer-token"
                ),
                Instant.parse("2026-01-01T00:00:00Z")
        ));

        assertTrue(principal.isPresent());
        assertEquals("internal-token", seenAccessToken.get());
        assertEquals(null, seenSessionId.get());
    }

    @Test
    void fallsBackToBearerAccessTokenForInternalBoundary() {
        AtomicReference<String> seenAccessToken = new AtomicReference<>();
        DefaultInternalServiceAuthenticationCapability capability = new DefaultInternalServiceAuthenticationCapability((accessToken, sessionId) -> {
            seenAccessToken.set(accessToken);
            return Optional.of(new PlatformAuthenticatedPrincipal("internal-service", java.util.Set.of("INTERNAL"), Map.of()));
        }, (principal, request) -> true);

        Optional<PlatformAuthenticatedPrincipal> principal = capability.authenticate(new SecurityRequest(
                null,
                "127.0.0.1",
                "/internal/sync",
                "POST",
                Map.of(PlatformAuthenticationFacade.ACCESS_TOKEN_ATTRIBUTE, "bearer-token"),
                Instant.parse("2026-01-01T00:00:00Z")
        ));

        assertTrue(principal.isPresent());
        assertEquals("bearer-token", seenAccessToken.get());
    }

    @Test
    void fallsBackToCompatibilityAdapterWhenTokenAuthenticationIsUnavailable() {
        DefaultInternalServiceAuthenticationCapability capability = new DefaultInternalServiceAuthenticationCapability(
                null,
                null,
                java.util.List.of(request -> Optional.of(new PlatformAuthenticatedPrincipal(
                        "compat-internal",
                        java.util.Set.of("ROLE_INTERNAL"),
                        Map.of("source", "legacy-secret")
                )))
        );

        Optional<PlatformAuthenticatedPrincipal> principal = capability.authenticate(new SecurityRequest(
                null,
                "127.0.0.1",
                "/internal/sync",
                "POST",
                Map.of(DefaultInternalServiceAuthenticationCapability.INTERNAL_REQUEST_SECRET_ATTRIBUTE, "debug-secret"),
                Instant.parse("2026-01-01T00:00:00Z")
        ));

        assertTrue(principal.isPresent());
        assertEquals("compat-internal", principal.get().userId());
    }
}
