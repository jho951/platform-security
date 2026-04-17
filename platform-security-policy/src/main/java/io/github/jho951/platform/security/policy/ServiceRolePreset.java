package io.github.jho951.platform.security.policy;

/**
 * platform-security starter가 선택하는 서비스 역할 preset이다.
 */
public enum ServiceRolePreset {
    /** 명시 설정만 사용하는 일반 mode다. */
    GENERAL,

    /** gateway처럼 edge ingress를 담당하는 서비스다. */
    EDGE,

    /** token/session 발급을 담당하는 identity issuer 서비스다. */
    ISSUER,

    /** JWT/API credential 검증 중심의 resource server다. */
    RESOURCE_SERVER,

    /** 내부 서비스 간 호출만 처리하는 service다. */
    INTERNAL_SERVICE
}
