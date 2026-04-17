package io.github.jho951.platform.security.policy;

import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityContext;

/**
 * 요청 attribute와 boundary를 기준으로 client type을 결정한다.
 */
public interface ClientTypeResolver {
    /**
     * 요청만으로 client type을 결정한다.
     *
     * @param request 정규화된 보안 요청
     * @return client type
     */
    ClientType resolve(SecurityRequest request);

    /**
     * 이미 해석된 context와 boundary까지 반영해 client type을 결정한다.
     *
     * @param request 정규화된 보안 요청
     * @param context 해석된 인증 context
     * @param boundary 요청 boundary
     * @return client type
     */
    default ClientType resolve(SecurityRequest request, SecurityContext context, SecurityBoundary boundary) {
        return resolve(request);
    }
}
