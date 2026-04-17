package io.github.jho951.platform.security.policy;

import io.github.jho951.platform.security.api.SecurityContext;

/**
 * 인증 context를 downstream propagation과 audit에 사용할 principal 문자열로 변환한다.
 */
public interface PlatformPrincipalFactory {
    /**
     * platform principal을 생성한다.
     *
     * @param context 해석된 인증 context
     * @return principal 문자열. anonymous이면 null일 수 있다
     */
    String createPrincipal(SecurityContext context);
}
