package io.github.jho951.platform.security.ip;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.SecurityBoundary;
import io.github.jho951.platform.security.policy.SecurityBoundaryType;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BoundaryAwareIpPolicyTest {
    @Test
    void inlineSourceAllowsAndDeniesAdminIps() {
        PlatformSecurityProperties.IpGuardProperties properties = new PlatformSecurityProperties.IpGuardProperties();
        properties.getAdmin().setRules(List.of("10.0.0.0/8"));

        DefaultBoundaryIpPolicyProvider provider = new DefaultBoundaryIpPolicyProvider(properties);
        var policy = provider.resolve(new SecurityBoundary(SecurityBoundaryType.ADMIN, List.of("/admin/**")));

        assertEquals(true, policy.evaluate(request("10.1.2.3"), context()).allowed());
        assertEquals(false, policy.evaluate(request("192.168.1.10"), context()).allowed());
    }

    @Test
    void legacyAdminAllowCidrsStillFeedInlineSource() {
        PlatformSecurityProperties.IpGuardProperties properties = new PlatformSecurityProperties.IpGuardProperties();
        properties.setAdminAllowCidrs(List.of("10.0.0.0/8"));

        DefaultBoundaryIpPolicyProvider provider = new DefaultBoundaryIpPolicyProvider(properties);
        var policy = provider.resolve(new SecurityBoundary(SecurityBoundaryType.ADMIN, List.of("/admin/**")));

        assertEquals(true, policy.evaluate(request("10.1.2.3"), context()).allowed());
    }

    @Test
    void cachingSourceUsesPreviousRulesInsideTtlAndReloadsAfterExpiry() throws Exception {
        AtomicInteger loads = new AtomicInteger();
        PlatformIpRuleSource delegate = () -> loads.incrementAndGet() == 1 ? "10.0.0.0/8" : "192.168.0.0/16";
        CachingPlatformIpRuleSource source = new CachingPlatformIpRuleSource(delegate, java.time.Duration.ofMillis(50), true);

        assertEquals("10.0.0.0/8", source.loadRules());
        assertEquals("10.0.0.0/8", source.loadRules());
        Thread.sleep(75);
        assertEquals("192.168.0.0/16", source.loadRules());
    }

    @Test
    void initialLoadFailureIsPropagated() {
        CachingPlatformIpRuleSource source = new CachingPlatformIpRuleSource(
                () -> {
                    throw new IllegalStateException("boom");
                },
                java.time.Duration.ZERO,
                true
        );

        assertThrows(IllegalStateException.class, source::loadRules);
    }

    @Test
    void reloadFailureCanKeepLastGoodRules() {
        AtomicInteger loads = new AtomicInteger();
        CachingPlatformIpRuleSource source = new CachingPlatformIpRuleSource(
                () -> {
                    if (loads.incrementAndGet() == 1) return "10.0.0.0/8";
                    throw new IllegalStateException("boom");
                },
                java.time.Duration.ZERO,
                true
        );

        assertEquals("10.0.0.0/8", source.loadRules());
        assertEquals("10.0.0.0/8", source.loadRules());
    }

    private SecurityRequest request(String ip) {
        return new SecurityRequest(
                "admin-1",
                ip,
                "/admin/users",
                "GET",
                Map.of(),
                Instant.parse("2026-01-01T00:00:00Z")
        );
    }

    private SecurityContext context() {
        return new SecurityContext(true, "admin-1", Set.of("ADMIN"), Map.of());
    }
}
