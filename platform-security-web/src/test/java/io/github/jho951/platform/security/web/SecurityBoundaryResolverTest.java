package io.github.jho951.platform.security.web;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SecurityBoundaryResolverTest {
    private final SecurityBoundaryResolver resolver = new SecurityBoundaryResolver();

    @Test
    void resolvesAndNormalizesPath() {
        assertEquals("/api", resolver.resolve("api"));
        assertEquals("/api/v1", resolver.resolve("  /api/v1  "));
    }

    @Test
    void rejectsBlankPath() {
        assertThrows(IllegalArgumentException.class, () -> resolver.resolve("   "));
    }
}
