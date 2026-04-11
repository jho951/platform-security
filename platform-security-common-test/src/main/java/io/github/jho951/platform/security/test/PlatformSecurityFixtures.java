package io.github.jho951.platform.security.test;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityRequest;

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
}
