package io.github.jho951.platform.security.api;

/**
 * 보안 정책 평가가 반환하는 최종 allow/deny 결정이다.
 */
public enum SecurityDecision {
    /** 요청을 계속 진행해도 된다. */
    ALLOW,

    /** 요청을 차단해야 한다. */
    DENY;

    /**
     * @return 요청 허용 결정이면 true
     */
    public boolean allowed() {
        return this == ALLOW;
    }
}
