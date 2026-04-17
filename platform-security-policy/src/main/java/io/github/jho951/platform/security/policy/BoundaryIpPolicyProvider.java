package io.github.jho951.platform.security.policy;

import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.ResolvedSecurityProfile;

/**
 * boundary별 IP guard 정책을 생성한다.
 *
 * <p>기본 구현은 admin/internal boundary에 allow-list 정책을 연결한다. 파일,
 * inline, policy-config 기반 rule source를 바꾸려면 이 provider나 rule source factory를
 * 교체한다.</p>
 */
public interface BoundaryIpPolicyProvider {
    /**
     * boundary에 맞는 IP 정책을 반환한다.
     *
     * @param boundary 요청 boundary
     * @return 평가할 보안 정책
     */
    SecurityPolicy resolve(SecurityBoundary boundary);

    /**
     * 이미 해석된 profile까지 반영해 boundary IP 정책을 반환한다.
     *
     * @param boundary 요청 boundary
     * @param profile 해석된 보안 profile
     * @return 평가할 보안 정책
     */
    default SecurityPolicy resolve(SecurityBoundary boundary, ResolvedSecurityProfile profile) {
        return resolve(boundary);
    }
}
