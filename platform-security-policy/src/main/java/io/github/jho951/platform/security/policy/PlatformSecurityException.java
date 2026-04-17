package io.github.jho951.platform.security.policy;

/**
 * platform-security 표준 오류 코드를 포함하는 runtime 예외다.
 */
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
