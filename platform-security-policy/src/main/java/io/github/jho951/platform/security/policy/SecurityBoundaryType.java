package io.github.jho951.platform.security.policy;

/**
 * platform-security가 구분하는 요청 boundary다.
 */
public enum SecurityBoundaryType {
    /** 인증 없이 접근 가능한 공개 endpoint다. */
    PUBLIC,

    /** 일반 인증이 필요한 보호 endpoint다. */
    PROTECTED,

    /** 관리자 권한과 admin IP guard가 필요한 endpoint다. */
    ADMIN,

    /** 내부 서비스 호출로 제한되는 endpoint다. */
    INTERNAL
}
