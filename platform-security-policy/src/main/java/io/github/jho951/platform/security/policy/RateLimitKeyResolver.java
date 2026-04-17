package io.github.jho951.platform.security.policy;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.ResolvedSecurityProfile;

/**
 * rate limiter가 사용할 bucket key를 요청과 인증 context에서 만든다.
 */
public interface RateLimitKeyResolver {
    /**
     * 기본 rate limit key를 반환한다.
     *
     * @param request 정규화된 보안 요청
     * @param context 해석된 인증 context
     * @return rate limit bucket key
     */
    String resolve(SecurityRequest request, SecurityContext context);

    /**
     * 해석된 보안 profile까지 반영해 rate limit key를 반환한다.
     *
     * @param request 정규화된 보안 요청
     * @param context 해석된 인증 context
     * @param profile 해석된 보안 profile
     * @return rate limit bucket key
     */
    default String resolve(SecurityRequest request, SecurityContext context, ResolvedSecurityProfile profile) {
        return resolve(request, context);
    }
}
