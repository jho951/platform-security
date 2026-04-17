package io.github.jho951.platform.security.api;

/**
 * 정제된 security audit event를 외부 감사 시스템으로 넘기는 hook이다.
 */
@FunctionalInterface
public interface SecurityAuditPublisher {
    /**
     * @param event 정제된 security audit event
     */
    void publish(SecurityAuditEvent event);

    /**
     * @return 아무 작업도 하지 않는 publisher
     */
    static SecurityAuditPublisher noop() {
        return event -> {
        };
    }
}
