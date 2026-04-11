package io.github.jho951.platform.security.api;

import java.util.Objects;

public record SecurityVerdict(SecurityDecision decision, String policy, String reason) {
    public SecurityVerdict {
        decision = Objects.requireNonNull(decision, "decision");
        policy = policy == null || policy.isBlank() ? "unknown" : policy.trim();
        reason = reason == null || reason.isBlank() ? null : reason.trim();
    }

    public boolean allowed() {
        return decision.allowed();
    }

    public static SecurityVerdict allow(String policy, String reason) {
        return new SecurityVerdict(SecurityDecision.ALLOW, policy, reason);
    }

    public static SecurityVerdict deny(String policy, String reason) {
        return new SecurityVerdict(SecurityDecision.DENY, policy, reason);
    }
}
