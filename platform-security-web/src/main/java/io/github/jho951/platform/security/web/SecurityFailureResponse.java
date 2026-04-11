package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.api.SecurityDecision;
import io.github.jho951.platform.security.api.SecurityVerdict;

public record SecurityFailureResponse(int status, String code, String message) {
    public SecurityFailureResponse {
        if (status < 100) {
            throw new IllegalArgumentException("status must be a valid HTTP status");
        }
        code = code == null || code.isBlank() ? "security.denied" : code.trim();
        message = message == null || message.isBlank() ? null : message.trim();
    }

    public static SecurityFailureResponse from(SecurityVerdict verdict) {
        if (verdict == null) throw new IllegalArgumentException("verdict must not be null");
        if (verdict.decision() == SecurityDecision.ALLOW) return new SecurityFailureResponse(200, "security.allowed", verdict.reason());
        return switch (verdict.policy()) {
            case "auth" -> new SecurityFailureResponse(401, "security.auth.required", verdict.reason());
            case "ip-guard" -> new SecurityFailureResponse(403, "security.ip.denied", verdict.reason());
            case "rate-limiter" -> new SecurityFailureResponse(429, "security.rate_limited", verdict.reason());
            default -> new SecurityFailureResponse(403, "security.denied", verdict.reason());
        };
    }
}
