package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DefaultClientIpResolverTest {
    @Test
    void ignoresForwardedForWhenTrustProxyIsDisabled() {
        PlatformSecurityProperties.IpGuardProperties properties = new PlatformSecurityProperties.IpGuardProperties();
        properties.setTrustProxy(false);
        DefaultClientIpResolver resolver = new DefaultClientIpResolver(properties);

        String resolved = resolver.resolve("10.0.0.10", Map.of("X-Forwarded-For", "1.2.3.4"));

        assertEquals("10.0.0.10", resolved);
    }

    @Test
    void usesForwardedForWhenTrustProxyIsEnabled() {
        PlatformSecurityProperties.IpGuardProperties properties = new PlatformSecurityProperties.IpGuardProperties();
        properties.setTrustProxy(true);
        DefaultClientIpResolver resolver = new DefaultClientIpResolver(properties);

        String resolved = resolver.resolve("10.0.0.10", Map.of("X-Forwarded-For", "1.2.3.4, 5.6.7.8"));

        assertEquals("1.2.3.4", resolved);
    }
}
