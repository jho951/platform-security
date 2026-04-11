package io.github.jho951.platform.security.testsupport;

import io.github.jho951.platform.security.policy.AuthMode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PlatformSecurityFixturesTest {
    @Test
    void gatewayPropertiesMatchExpectedDefaults() {
        var properties = PlatformSecurityFixtures.gatewayServerProperties();
        assertEquals(AuthMode.HYBRID, properties.getAuth().getDefaultMode());
        assertTrue(properties.getBoundary().getPublicPaths().contains("/health"));
        assertTrue(properties.getBoundary().getProtectedPaths().contains("/api/**"));
    }

    @Test
    void authServerPropertiesExposeAuthEndpoints() {
        var properties = PlatformSecurityFixtures.authServerProperties();
        assertTrue(properties.getBoundary().getPublicPaths().contains("/auth/login"));
        assertTrue(properties.getBoundary().getPublicPaths().contains("/auth/refresh"));
        assertTrue(properties.getBoundary().getPublicPaths().contains("/auth/logout"));
    }
}
