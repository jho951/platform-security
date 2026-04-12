package io.github.jho951.platform.security.auth;

import io.github.jho951.platform.security.api.SecurityRequest;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class PlatformSecurityContextResolversTest {
    @Test
    void devFallbackResolverIsAvailable() {
        assertNotNull(PlatformSecurityContextResolvers.devFallback());
    }

    @Test
    void anonymousResolverProducesAnonymousContext() {
        var resolver = PlatformSecurityContextResolvers.anonymous();
        var context = resolver.resolve(new SecurityRequest(
                null,
                "127.0.0.1",
                "/health",
                "GET",
                Map.of(),
                Instant.parse("2026-01-01T00:00:00Z")
        ));

        assertFalse(context.authenticated());
        assertNotNull(context.attributes());
    }
}
