package io.github.jho951.platform.security.policy;

/**
 * 요청을 보낸 client의 실행 성격이다.
 */
public enum ClientType {
    /** browser session 중심 client다. */
    BROWSER,

    /** 외부 API client다. */
    EXTERNAL_API,

    /** 내부 서비스 간 호출이다. */
    INTERNAL_SERVICE,

    /** admin console 또는 운영자 도구 호출이다. */
    ADMIN_CONSOLE
}
