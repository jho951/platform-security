package io.github.jho951.platform.security.core;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityEvaluationResult;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.policy.DefaultAuthenticationModeResolver;
import io.github.jho951.platform.security.policy.DefaultClientTypeResolver;
import io.github.jho951.platform.security.policy.DefaultPlatformPrincipalFactory;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.SecurityBoundaryType;
import io.github.jho951.platform.security.web.PathPatternSecurityBoundaryResolver;
import io.github.jho951.platform.security.ip.DefaultBoundaryIpPolicyProvider;
import io.github.jho951.platform.security.ratelimit.DefaultBoundaryRateLimitPolicyProvider;
import io.github.jho951.platform.security.ratelimit.DefaultRateLimitKeyResolver;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultSecurityEvaluationServiceTest {
    @Test
    void returnsResolvedSecurityProfileForBoundaryAndAuthModeSelection() {
        PlatformSecurityProperties properties = new PlatformSecurityProperties();
        properties.getBoundary().setPublicPaths(List.of("/health"));
        properties.getBoundary().setProtectedPaths(List.of("/api/**"));
        properties.getBoundary().setAdminPaths(List.of("/admin/**"));
        properties.getBoundary().setInternalPaths(List.of("/internal/**"));

        DefaultSecurityEvaluationService service = new DefaultSecurityEvaluationService(
                new PathPatternSecurityBoundaryResolver(
                        properties.getBoundary().getPublicPaths(),
                        properties.getBoundary().getProtectedPaths(),
                        properties.getBoundary().getAdminPaths(),
                        properties.getBoundary().getInternalPaths()
                ),
                new DefaultClientTypeResolver(),
                new DefaultAuthenticationModeResolver(properties.getAuth()),
                new DefaultBoundaryIpPolicyProvider(properties.getIpGuard()),
                new DefaultBoundaryRateLimitPolicyProvider(properties.getRateLimit(), new DefaultRateLimitKeyResolver()),
                new DefaultPlatformPrincipalFactory()
        );

        SecurityEvaluationResult result = service.evaluateResult(
                new SecurityRequest(
                        "user-1",
                        "127.0.0.1",
                        "/admin/users",
                        "read",
                        Map.of(
                                "auth.sessionId", "session-1",
                                "auth.accessToken", "token-1"
                        ),
                        Instant.parse("2026-01-01T00:00:00Z")
                ),
                new SecurityContext(true, "user-1", Set.of("ADMIN"), Map.of())
        );

        assertEquals(SecurityBoundaryType.ADMIN.name(), result.evaluationContext().profile().boundaryType());
        assertEquals("ADMIN_CONSOLE", result.evaluationContext().profile().clientType());
        assertEquals("HYBRID", result.evaluationContext().profile().authMode());
        assertEquals(List.of("/admin/**"), result.evaluationContext().profile().boundaryPatterns());
        assertTrue(result.verdict().allowed());
    }
}
