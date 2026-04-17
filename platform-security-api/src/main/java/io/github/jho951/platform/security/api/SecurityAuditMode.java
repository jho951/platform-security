package io.github.jho951.platform.security.api;

/**
 * security audit event 발행 범위를 정의한다.
 */
public enum SecurityAuditMode {
    DENY_ONLY,
    DENY_AND_ADMIN,
    INTERNAL_AND_ADMIN,
    ALL;

    /**
     * @param event 정제된 security audit event
     * @return 현재 mode에서 발행 대상이면 true
     */
    public boolean shouldPublish(SecurityAuditEvent event) {
        if (event == null) {
            return false;
        }
        return switch (this) {
            case DENY_ONLY -> !event.allowed();
            case DENY_AND_ADMIN -> !event.allowed() || "ADMIN".equalsIgnoreCase(event.boundaryType());
            case INTERNAL_AND_ADMIN -> "INTERNAL".equalsIgnoreCase(event.boundaryType())
                    || "ADMIN".equalsIgnoreCase(event.boundaryType());
            case ALL -> true;
        };
    }
}
