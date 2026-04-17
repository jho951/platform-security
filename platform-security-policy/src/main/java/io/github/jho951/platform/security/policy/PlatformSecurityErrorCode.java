package io.github.jho951.platform.security.policy;

/**
 * platform-security가 외부 응답과 예외에 사용하는 표준 오류 코드다.
 */
public enum PlatformSecurityErrorCode {
    /** 인증이 필요하거나 인증 context가 없다. */
    SECURITY_AUTH_REQUIRED,

    /** IP guard 정책이 요청 IP를 거부했다. */
    SECURITY_IP_DENIED,

    /** rate limit 정책이 요청을 제한했다. */
    SECURITY_RATE_LIMITED,

    /** 그 밖의 보안 정책이 요청을 거부했다. */
    SECURITY_DENIED
}
