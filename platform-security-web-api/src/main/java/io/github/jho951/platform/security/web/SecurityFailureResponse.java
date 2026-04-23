package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.api.SecurityDecision;
import io.github.jho951.platform.security.api.SecurityVerdict;

/**
 * 보안 verdict를 HTTP 실패 응답으로 변환한 값이다.
 *
 * @param status HTTP 상태 코드
 * @param code 응답과 로그에 사용할 표준 오류 코드
 * @param message 실패 사유
 */
public record SecurityFailureResponse(int status, String code, String message) {
    public SecurityFailureResponse {
        if (status < 100) {
            throw new IllegalArgumentException("status must be a valid HTTP status");
        }
        code = code == null || code.isBlank() ? "security.denied" : code.trim();
        message = message == null || message.isBlank() ? null : message.trim();
    }

    /**
     * verdict를 표준 HTTP 실패 응답으로 변환한다.
     *
     * @param verdict 보안 평가 verdict
     * @return HTTP 응답 표현
     */
    public static SecurityFailureResponse from(SecurityVerdict verdict) {
        if (verdict == null) {
            throw new IllegalArgumentException("verdict must not be null");
        }
        if (verdict.decision() == SecurityDecision.ALLOW) {
            return new SecurityFailureResponse(200, "security.allowed", verdict.reason());
        }
        return switch (verdict.policy()) {
            case "auth" -> new SecurityFailureResponse(401, "security.auth.required", verdict.reason());
            case "ip-guard" -> new SecurityFailureResponse(403, "security.ip.denied", verdict.reason());
            case "rate-limiter" -> new SecurityFailureResponse(429, "security.rate_limited", verdict.reason());
            default -> new SecurityFailureResponse(403, "security.denied", verdict.reason());
        };
    }
}
