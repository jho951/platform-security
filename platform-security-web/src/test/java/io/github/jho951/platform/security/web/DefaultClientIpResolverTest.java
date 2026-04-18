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
    void ignoresForwardedForWhenTrustedProxyCidrsAreEmpty() {
        PlatformSecurityProperties.IpGuardProperties properties = new PlatformSecurityProperties.IpGuardProperties();
        properties.setTrustProxy(true);
        DefaultClientIpResolver resolver = new DefaultClientIpResolver(properties);

        String resolved = resolver.resolve("10.0.0.10", Map.of("X-Forwarded-For", "1.2.3.4, 5.6.7.8"));

        assertEquals("10.0.0.10", resolved);
    }

    @Test
    void usesForwardedForWhenLoopbackProxyIsExplicitlyTrusted() {
        PlatformSecurityProperties.IpGuardProperties properties = new PlatformSecurityProperties.IpGuardProperties();
        properties.setTrustProxy(true);
        properties.setTrustedProxyCidrs(java.util.List.of("127.0.0.1", "::1"));
        DefaultClientIpResolver resolver = new DefaultClientIpResolver(properties);

        assertEquals("1.2.3.4", resolver.resolve("127.0.0.1", Map.of("X-Forwarded-For", "1.2.3.4")));
        assertEquals("1.2.3.4", resolver.resolve("::1", Map.of("X-Forwarded-For", "1.2.3.4")));
    }

    @Test
    void resolvesRightmostUntrustedForwardedIpWhenTrustedCidrsAreConfigured() {
        PlatformSecurityProperties.IpGuardProperties properties = new PlatformSecurityProperties.IpGuardProperties();
        properties.setTrustProxy(true);
        properties.setTrustedProxyCidrs(java.util.List.of("10.0.0.0/8", "172.16.0.0/12"));
        DefaultClientIpResolver resolver = new DefaultClientIpResolver(properties);

        String resolved = resolver.resolve(
                "10.0.0.10",
                Map.of("X-Forwarded-For", "198.51.100.1, 203.0.113.9, 172.16.2.20, 10.0.0.9")
        );

        assertEquals("203.0.113.9", resolved);
    }

    @Test
    void ignoresInvalidForwardedForEntries() {
        PlatformSecurityProperties.IpGuardProperties properties = new PlatformSecurityProperties.IpGuardProperties();
        properties.setTrustProxy(true);
        properties.setTrustedProxyCidrs(java.util.List.of("10.0.0.0/8"));
        DefaultClientIpResolver resolver = new DefaultClientIpResolver(properties);

        String resolved = resolver.resolve(
                "10.0.0.10",
                Map.of("X-Forwarded-For", "unknown, , 203.0.113.9, 10.0.0.9")
        );

        assertEquals("203.0.113.9", resolved);
    }

    @Test
    void fallsBackToRemoteAddressWhenForwardedForOnlyContainsTrustedProxies() {
        PlatformSecurityProperties.IpGuardProperties properties = new PlatformSecurityProperties.IpGuardProperties();
        properties.setTrustProxy(true);
        properties.setTrustedProxyCidrs(java.util.List.of("10.0.0.0/8"));
        DefaultClientIpResolver resolver = new DefaultClientIpResolver(properties);

        String resolved = resolver.resolve(
                "10.0.0.10",
                Map.of("X-Forwarded-For", "10.0.0.9, 10.0.0.8")
        );

        assertEquals("10.0.0.10", resolved);
    }

    @Test
    void usesForwardedForOnlyFromTrustedProxyWhenTrustedCidrsAreConfigured() {
        PlatformSecurityProperties.IpGuardProperties properties = new PlatformSecurityProperties.IpGuardProperties();
        properties.setTrustProxy(true);
        properties.setTrustedProxyCidrs(java.util.List.of("10.0.0.0/8"));
        DefaultClientIpResolver resolver = new DefaultClientIpResolver(properties);

        assertEquals("1.2.3.4", resolver.resolve("10.0.0.10", Map.of("X-Forwarded-For", "1.2.3.4")));
        assertEquals("192.168.1.10", resolver.resolve("192.168.1.10", Map.of("X-Forwarded-For", "1.2.3.4")));
    }

    @Test
    void usesSharedMatcherForIpv6TrustedProxyCidrs() {
        PlatformSecurityProperties.IpGuardProperties properties = new PlatformSecurityProperties.IpGuardProperties();
        properties.setTrustProxy(true);
        properties.setTrustedProxyCidrs(java.util.List.of("2001:db8::/64"));
        DefaultClientIpResolver resolver = new DefaultClientIpResolver(properties);

        assertEquals("1.2.3.4", resolver.resolve("2001:db8::10", Map.of("X-Forwarded-For", "1.2.3.4")));
        assertEquals("2001:db9::10", resolver.resolve("2001:db9::10", Map.of("X-Forwarded-For", "1.2.3.4")));
    }
}
