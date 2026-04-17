package io.github.jho951.platform.security.policy;

import io.github.jho951.platform.security.api.SecurityRequest;

/**
 * 요청 path를 platform-security boundary로 분류한다.
 */
public interface SecurityBoundaryResolver {
    /**
     * 요청이 속한 boundary를 반환한다.
     *
     * @param request 정규화된 보안 요청
     * @return 해석된 boundary
     */
    SecurityBoundary resolve(SecurityRequest request);
}
