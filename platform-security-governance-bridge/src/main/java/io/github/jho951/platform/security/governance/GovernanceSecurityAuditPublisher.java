package io.github.jho951.platform.security.governance;

import io.github.jho951.platform.governance.api.AuditEntry;
import io.github.jho951.platform.governance.api.AuditLogRecorder;
import io.github.jho951.platform.security.api.ResolvedSecurityProfile;
import io.github.jho951.platform.security.api.SecurityEvaluationResult;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.web.SecurityAuditPublisher;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * platform-security 평가 결과를 platform-governance 감사 entry로 변환하는 publisher다.
 *
 * <p>보안 verdict, boundary, client type, auth mode, path, action, client IP, principal을
 * 표준 attribute로 기록한다.</p>
 */
public final class GovernanceSecurityAuditPublisher implements SecurityAuditPublisher {
    private final AuditLogRecorder auditLogRecorder;

    public GovernanceSecurityAuditPublisher(AuditLogRecorder auditLogRecorder) {
        this.auditLogRecorder = Objects.requireNonNull(auditLogRecorder, "auditLogRecorder");
    }

    @Override
    public void publish(SecurityEvaluationResult evaluationResult) {
        Objects.requireNonNull(evaluationResult, "evaluationResult");
        SecurityRequest request = evaluationResult.evaluationContext().request();
        ResolvedSecurityProfile profile = evaluationResult.evaluationContext().profile();
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("security.allowed", Boolean.toString(evaluationResult.verdict().allowed()));
        attributes.put("security.policy", evaluationResult.verdict().policy());
        if (evaluationResult.verdict().reason() != null) {
            attributes.put("security.reason", evaluationResult.verdict().reason());
        }
        attributes.put("security.boundary", profile.boundaryType());
        attributes.put("security.client-type", profile.clientType());
        attributes.put("security.auth-mode", profile.authMode());
        attributes.put("security.path", request.path());
        attributes.put("security.action", request.action());
        attributes.put("security.client-ip", request.clientIp());
        String principal = evaluationResult.evaluationContext().securityContext().principal();
        if (principal != null && !principal.isBlank()) {
            attributes.put("security.principal", principal);
        }
        auditLogRecorder.record(new AuditEntry(
                "security",
                "security evaluated",
                attributes,
                request.occurredAt()
        ));
    }
}
