package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.policy.SecurityBoundaryType;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SecurityBoundaryResolverTest {
    private final PathPatternSecurityBoundaryResolver resolver = new PathPatternSecurityBoundaryResolver();

    @Test
    void resolvesBoundaryAndNormalizesPath() {
        assertEquals("/api", resolver.resolvePath("api"));
        assertEquals("/api/v1", resolver.resolvePath("  /api/v1  "));
        assertEquals(
                SecurityBoundaryType.ADMIN,
                resolver.resolve(new SecurityRequest(null, "127.0.0.1", "/admin/users", "read", Map.of(), Instant.parse("2026-01-01T00:00:00Z"))).type()
        );
    }

    @Test
    void rejectsBlankPath() {
        assertThrows(IllegalArgumentException.class, () -> resolver.resolvePath("   "));
    }
}
