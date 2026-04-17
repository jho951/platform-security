package io.github.jho951.platform.security.api;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * audit sink로 넘길 수 있도록 정제된 security 평가 event다.
 *
 * <p>원본 request attribute를 그대로 노출하지 않고, 운영 감사에 필요한 표준 field만 담는다.</p>
 *
 * @param allowed 요청 허용 여부
 * @param decision security decision
 * @param policy verdict를 낸 policy 이름
 * @param reason verdict 사유
 * @param boundaryType resolved boundary type
 * @param clientType resolved client type
 * @param authMode resolved auth mode
 * @param path 요청 path
 * @param action 요청 action
 * @param clientIp client IP
 * @param principal principal id
 * @param occurredAt 요청 발생 시각
 */
public record SecurityAuditEvent(
        boolean allowed,
        SecurityDecision decision,
        String policy,
        String reason,
        String boundaryType,
        String clientType,
        String authMode,
        String path,
        String action,
        String clientIp,
        String principal,
        Instant occurredAt
) {
    public SecurityAuditEvent {
        policy = trimToNull(policy);
        reason = trimToNull(reason);
        boundaryType = trimToNull(boundaryType);
        clientType = trimToNull(clientType);
        authMode = trimToNull(authMode);
        path = trimToNull(path);
        action = trimToNull(action);
        clientIp = trimToNull(clientIp);
        principal = trimToNull(principal);
        occurredAt = occurredAt == null ? Instant.now() : occurredAt;
    }

    /**
     * @param evaluationResult security 평가 결과
     * @return raw attribute가 제거된 audit event
     */
    public static SecurityAuditEvent from(SecurityEvaluationResult evaluationResult) {
        SecurityEvaluationContext context = evaluationResult.evaluationContext();
        SecurityRequest request = context.request();
        SecurityContext securityContext = context.securityContext();
        ResolvedSecurityProfile profile = context.profile();
        SecurityVerdict verdict = evaluationResult.verdict();
        return new SecurityAuditEvent(
                verdict.allowed(),
                verdict.decision(),
                verdict.policy(),
                verdict.reason(),
                profile.boundaryType(),
                profile.clientType(),
                profile.authMode(),
                request.path(),
                request.action(),
                request.clientIp(),
                securityContext.principal(),
                request.occurredAt()
        );
    }

    /**
     * governance 등 외부 audit backend에 넘길 표준 attribute map이다.
     */
    public Map<String, String> attributes() {
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("security.allowed", Boolean.toString(allowed));
        attributes.put("security.decision", decision.name());
        putIfPresent(attributes, "security.policy", policy);
        putIfPresent(attributes, "security.reason", reason);
        putIfPresent(attributes, "security.boundary", boundaryType);
        putIfPresent(attributes, "security.client-type", clientType);
        putIfPresent(attributes, "security.auth-mode", authMode);
        putIfPresent(attributes, "security.path", path);
        putIfPresent(attributes, "security.action", action);
        putIfPresent(attributes, "security.client-ip", clientIp);
        putIfPresent(attributes, "security.principal", principal);
        return Map.copyOf(attributes);
    }

    private static void putIfPresent(Map<String, String> attributes, String key, String value) {
        if (value != null) {
            attributes.put(key, value);
        }
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
