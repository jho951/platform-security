package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityEvaluationContext;
import io.github.jho951.platform.security.api.SecurityEvaluationResult;
import io.github.jho951.platform.security.api.ResolvedSecurityProfile;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SecurityDownstreamIdentityPropagatorTest {
    @Test
    void propagatesResolvedIdentityHeaders() {
        SecurityRequest request = new SecurityRequest(
                "user-1",
                "127.0.0.1",
                "/api/orders",
                "GET",
                Map.of(),
                Instant.parse("2026-01-01T00:00:00Z")
        );
        SecurityContext context = new SecurityContext(true, "user-1", Set.of("USER"), Map.of());
        SecurityEvaluationResult result = new SecurityEvaluationResult(
                new SecurityEvaluationContext(
                        request,
                        context,
                        new ResolvedSecurityProfile(
                                "PROTECTED",
                                java.util.List.of("/api/**"),
                                "EXTERNAL_API",
                                "JWT"
                        )
                ),
                SecurityVerdict.allow("auth", "ok")
        );

        SecurityDownstreamHeaders headers = new SecurityDownstreamIdentityPropagator().propagate(result);

        assertEquals("PROTECTED", headers.asMap().get("X-Security-Boundary"));
        assertEquals("EXTERNAL_API", headers.asMap().get("X-Security-Client-Type"));
        assertEquals("JWT", headers.asMap().get("X-Security-Auth-Mode"));
        assertEquals("user-1", headers.asMap().get("X-Security-Principal"));
        assertEquals("ALLOW", headers.asMap().get("X-Security-Decision"));
        assertEquals("auth", headers.asMap().get("X-Security-Policy"));
    }
}
