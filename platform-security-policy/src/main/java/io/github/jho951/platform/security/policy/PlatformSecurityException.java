package io.github.jho951.platform.security.policy;

public class PlatformSecurityException extends RuntimeException {
    private final PlatformSecurityErrorCode errorCode;

    public PlatformSecurityException(PlatformSecurityErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode == null ? PlatformSecurityErrorCode.SECURITY_DENIED : errorCode;
    }

    public PlatformSecurityErrorCode getErrorCode() {
        return errorCode;
    }
}
