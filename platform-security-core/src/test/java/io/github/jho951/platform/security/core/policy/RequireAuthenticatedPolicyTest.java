package io.github.jho951.platform.security.core.policy;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityDecision;
import io.github.jho951.platform.security.api.SecurityRequest;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RequireAuthenticatedPolicyTest {
    @Test
    void deniesAnonymousRequest() {
        RequireAuthenticatedPolicy policy = new RequireAuthenticatedPolicy();

        assertEquals(SecurityDecision.DENY, policy.evaluate(
                new SecurityRequest("user-1", "127.0.0.1", "/api", "read", Map.of(), Instant.parse("2026-01-01T00:00:00Z")),
                new SecurityContext(false, null, Set.of(), Map.of())
        ).decision());
    }
}
