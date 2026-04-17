package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.hybrid.HybridAuthenticationContext;
import io.github.jho951.platform.security.api.SecurityRequest;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultInternalServiceAuthenticationCapabilityTest {
    @Test
    void usesDedicatedInternalTokenWhenPresent() {
        AtomicReference<HybridAuthenticationContext> seen = new AtomicReference<>();
        DefaultInternalServiceAuthenticationCapability capability = new DefaultInternalServiceAuthenticationCapability(context -> {
            seen.set(context);
            return Optional.of(new Principal("internal-service", List.of("INTERNAL"), Map.of()));
        }, (principal, request) -> true);

        Optional<Principal> principal = capability.authenticate(new SecurityRequest(
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
        assertEquals(Optional.of("internal-token"), seen.get().accessToken());
    }

    @Test
    void fallsBackToBearerAccessTokenForInternalBoundary() {
        AtomicReference<HybridAuthenticationContext> seen = new AtomicReference<>();
        DefaultInternalServiceAuthenticationCapability capability = new DefaultInternalServiceAuthenticationCapability(context -> {
            seen.set(context);
            return Optional.of(new Principal("internal-service", List.of("INTERNAL"), Map.of()));
        }, (principal, request) -> true);

        Optional<Principal> principal = capability.authenticate(new SecurityRequest(
                null,
                "127.0.0.1",
                "/internal/sync",
                "POST",
                Map.of(PlatformAuthenticationFacade.ACCESS_TOKEN_ATTRIBUTE, "bearer-token"),
                Instant.parse("2026-01-01T00:00:00Z")
        ));

        assertTrue(principal.isPresent());
        assertEquals(Optional.of("bearer-token"), seen.get().accessToken());
    }
}
