package io.github.jho951.platform.security.core.policy;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityDecision;
import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.core.DefaultSecurityPolicyService;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultSecurityPolicyServiceTest {
    @Test
    void deniesWhenAuthenticationFails() {
        SecurityPolicy service = new DefaultSecurityPolicyService(List.of(new RequireAuthenticatedPolicy()));
        SecurityVerdict verdict = service.evaluate(
                new SecurityRequest("user-1", "127.0.0.1", "/api", "read", Map.of(), Instant.parse("2026-01-01T00:00:00Z")),
                new SecurityContext(false, null, Set.of(), Map.of())
        );

        assertEquals(SecurityDecision.DENY, verdict.decision());
        assertTrue(verdict.reason().contains("authentication"));
    }
}
