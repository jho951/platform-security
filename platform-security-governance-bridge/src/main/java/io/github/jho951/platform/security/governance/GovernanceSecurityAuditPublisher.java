package io.github.jho951.platform.security.governance;

import io.github.jho951.platform.governance.api.AuditEntry;
import io.github.jho951.platform.governance.api.AuditLogRecorder;
import io.github.jho951.platform.security.api.SecurityAuditEvent;
import io.github.jho951.platform.security.api.SecurityAuditMode;
import io.github.jho951.platform.security.api.SecurityAuditPublisher;

import java.util.Objects;

/**
 * platform-security 평가 결과를 platform-governance 감사 entry로 변환하는 publisher다.
 *
 * <p>보안 verdict, boundary, client type, auth mode, path, action, client IP, principal을
 * 표준 attribute로 기록한다.</p>
 */
public final class GovernanceSecurityAuditPublisher implements SecurityAuditPublisher {
    private final AuditLogRecorder auditLogRecorder;
    private final SecurityAuditMode auditMode;

    public GovernanceSecurityAuditPublisher(AuditLogRecorder auditLogRecorder) {
        this(auditLogRecorder, SecurityAuditMode.DENY_AND_ADMIN);
    }

    public GovernanceSecurityAuditPublisher(AuditLogRecorder auditLogRecorder, SecurityAuditMode auditMode) {
        this.auditLogRecorder = Objects.requireNonNull(auditLogRecorder, "auditLogRecorder");
        this.auditMode = auditMode == null ? SecurityAuditMode.DENY_AND_ADMIN : auditMode;
    }

    @Override
    public void publish(SecurityAuditEvent event) {
        Objects.requireNonNull(event, "event");
        if (!auditMode.shouldPublish(event)) {
            return;
        }
        auditLogRecorder.record(new AuditEntry(
                "security",
                "security evaluated",
                event.attributes(),
                event.occurredAt()
        ));
    }
}
