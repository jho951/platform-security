package io.github.jho951.platform.security.spring;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityDecision;
import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.web.SecurityContextResolver;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class PlatformSecurityAutoConfigurationTest {
    private final PlatformSecurityAutoConfiguration configuration = new PlatformSecurityAutoConfiguration();

    @Test
    void authPolicyAllowsWhenDisabled() {
        PlatformSecurityProperties properties = new PlatformSecurityProperties();
        properties.getAuthentication().setRequired(false);

        SecurityPolicy policy = configuration.authPolicy(properties);
        SecurityVerdict verdict = policy.evaluate(
                new SecurityRequest("user-1", "127.0.0.1", "/api", "read", Map.of(), Instant.parse("2026-01-01T00:00:00Z")),
                new SecurityContext(false, null, Set.of(), Map.of())
        );

        assertEquals(SecurityDecision.ALLOW, verdict.decision());
        assertEquals("auth", policy.name());
    }

    @Test
    void rateLimitPolicyUsesFixedWindowFallback() {
        PlatformSecurityProperties properties = new PlatformSecurityProperties();
        properties.getRateLimit().setEnabled(true);
        properties.getRateLimit().setLimit(1);
        properties.getRateLimit().setWindow(Duration.ofMinutes(1));

        SecurityPolicy policy = configuration.rateLimitPolicy(properties);

        SecurityRequest request = new SecurityRequest("user-1", "127.0.0.1", "/api", "read", Map.of(), Instant.parse("2026-01-01T00:00:00Z"));
        SecurityContext context = new SecurityContext(true, "user-1", Set.of("USER"), Map.of());

        assertEquals(SecurityDecision.ALLOW, policy.evaluate(request, context).decision());
        assertEquals(SecurityDecision.DENY, policy.evaluate(request, context).decision());
    }

    @Test
    void securityContextResolverExists() {
        PlatformSecurityProperties properties = new PlatformSecurityProperties();
        SecurityContextResolver resolver = configuration.securityContextResolver(properties);

        assertNotNull(resolver);
    }

    @Test
    void clockBeanExists() {
        assertNotNull(configuration.platformSecurityClock());
    }
}
