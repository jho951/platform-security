package io.github.jho951.platform.security.core.policy;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityDecision;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class IpAllowListPolicyTest {
    @Test
    void deniesUnknownIp() {
        IpAllowListPolicy policy = new IpAllowListPolicy(List.of("10.0.0.1"));
        SecurityVerdict verdict = policy.evaluate(
                new SecurityRequest("user-1", "127.0.0.1", "/api", "read", Map.of(), Instant.parse("2026-01-01T00:00:00Z")),
                new SecurityContext(true, "user-1", Set.of("USER"), Map.of())
        );

        assertEquals(SecurityDecision.DENY, verdict.decision());
    }

    @Test
    void allowsCidrFromLegacyList() {
        IpAllowListPolicy policy = new IpAllowListPolicy(List.of("10.0.0.0/8"));
        SecurityVerdict verdict = policy.evaluate(
                new SecurityRequest("user-1", "10.1.2.3", "/api", "read", Map.of(), Instant.parse("2026-01-01T00:00:00Z")),
                new SecurityContext(true, "user-1", Set.of("USER"), Map.of())
        );

        assertEquals(SecurityDecision.ALLOW, verdict.decision());
    }
}
