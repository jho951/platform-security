package io.github.jho951.platform.security.api;

import java.util.Objects;

/**
 * machine-readable policy 이름과 사유를 포함한 보안 결정이다.
 *
 * @param decision allow 또는 deny 결정
 * @param policy verdict를 만든 policy 이름
 * @param reason 감사와 진단에 사용할 수 있는 사유
 */
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
