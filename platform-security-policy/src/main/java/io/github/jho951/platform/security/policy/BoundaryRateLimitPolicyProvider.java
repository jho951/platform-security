package io.github.jho951.platform.security.policy;

import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.ResolvedSecurityProfile;

/**
 * boundary와 route profile에 맞는 rate limit 정책을 생성한다.
 */
public interface BoundaryRateLimitPolicyProvider {
    /**
     * boundary 기준 rate limit 정책을 반환한다.
     *
     * @param boundary 요청 boundary
     * @return 평가할 rate limit 정책
     */
    SecurityPolicy resolve(SecurityBoundary boundary);

    /**
     * 해석된 profile까지 반영해 rate limit 정책을 반환한다.
     *
     * @param boundary 요청 boundary
     * @param profile 해석된 보안 profile
     * @return 평가할 rate limit 정책
     */
    default SecurityPolicy resolve(SecurityBoundary boundary, ResolvedSecurityProfile profile) {
        return resolve(boundary);
    }
}
