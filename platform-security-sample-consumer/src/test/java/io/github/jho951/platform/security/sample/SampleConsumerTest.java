package io.github.jho951.platform.security.sample;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityEvaluationResult;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.core.DefaultSecurityPolicyService;
import io.github.jho951.platform.security.ip.DefaultBoundaryIpPolicyProvider;
import io.github.jho951.platform.security.policy.DefaultAuthenticationModeResolver;
import io.github.jho951.platform.security.policy.DefaultClientTypeResolver;
import io.github.jho951.platform.security.policy.DefaultPlatformPrincipalFactory;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.ratelimit.DefaultBoundaryRateLimitPolicyProvider;
import io.github.jho951.platform.security.ratelimit.DefaultRateLimitKeyResolver;
import io.github.jho951.platform.security.testsupport.PlatformSecurityFixtures;
import io.github.jho951.platform.security.web.PathPatternSecurityBoundaryResolver;
import io.github.jho951.platform.security.web.SecurityIngressAdapter;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SampleConsumerTest {
    @Test
    void gatewaySampleUsesBoundaryAwareSelection() {
        PlatformSecurityProperties properties = PlatformSecurityFixtures.gatewayServerProperties();
        properties.getIpGuard().setAdminAllowCidrs(java.util.List.of("10.0.0.0/8"));

        SecurityIngressAdapter adapter = adapter(properties);
        SecurityVerdict verdict = adapter.evaluate(
                new SecurityRequest(
                        "admin-1",
                        "10.10.2.15",
                        "/admin/users",
                        "GET",
                        Map.of(
                                "auth.sessionId", "session-1",
                                "auth.accessToken", "token-1"
                        ),
                        java.time.Instant.parse("2026-01-01T00:00:00Z")
                ),
                new SecurityContext(true, "admin-1", Set.of("ADMIN"), Map.of())
        );

        assertTrue(verdict.allowed(), () -> verdict.policy() + ":" + verdict.reason());
    }

    @Test
    void authServerSampleUsesPresetAndCanBeOverridden() {
        PlatformSecurityProperties properties = PlatformSecurityFixtures.authServerProperties();
        SecurityIngressAdapter adapter = adapter(properties);

        SecurityEvaluationResult result = adapter.evaluateResult(
                new SecurityRequest(
                        "user-1",
                        "127.0.0.1",
                        "/auth/login",
                        "POST",
                        Map.of("auth.sessionId", "session-1"),
                        java.time.Instant.parse("2026-01-01T00:00:00Z")
                ),
                new SecurityContext(true, "user-1", Set.of("USER"), Map.of())
        );

        assertEquals("PUBLIC", result.evaluationContext().profile().boundaryType());
        assertEquals("NONE", result.evaluationContext().profile().authMode());
        assertTrue(result.verdict().allowed());
    }

    private SecurityIngressAdapter adapter(PlatformSecurityProperties properties) {
        var boundaryResolver = new PathPatternSecurityBoundaryResolver(
                properties.getBoundary().getPublicPaths(),
                properties.getBoundary().getProtectedPaths(),
                properties.getBoundary().getAdminPaths(),
                properties.getBoundary().getInternalPaths()
        );
        var service = new DefaultSecurityPolicyService(
                boundaryResolver,
                new DefaultClientTypeResolver(),
                new DefaultAuthenticationModeResolver(properties.getAuth()),
                new DefaultBoundaryIpPolicyProvider(properties.getIpGuard()),
                new DefaultBoundaryRateLimitPolicyProvider(properties.getRateLimit(), new DefaultRateLimitKeyResolver()),
                new DefaultPlatformPrincipalFactory()
        );
        return new SecurityIngressAdapter(service, boundaryResolver);
    }
}
