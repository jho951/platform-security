package io.github.jho951.platform.security.policy;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityRequest;

/**
 * 요청 boundary, client type, credential hint를 기준으로 사용할 인증 방식을 결정한다.
 *
 * <p>기본 구현은 request attribute와 {@link PlatformSecurityProperties.AuthProperties}
 * 설정을 사용한다. 서비스가 더 강한 credential routing이 필요하면 이 SPI를 교체한다.</p>
 */
public interface AuthenticationModeResolver {
    /**
     * 요청과 인증 context만으로 인증 방식을 결정한다.
     *
     * @param request 정규화된 보안 요청
     * @param context 해석된 인증 context
     * @return 선택된 인증 방식
     */
    AuthMode resolve(SecurityRequest request, SecurityContext context);

    /**
     * 이미 해석된 boundary와 client type까지 반영해 인증 방식을 결정한다.
     *
     * @param request 정규화된 보안 요청
     * @param context 해석된 인증 context
     * @param boundary 요청 boundary
     * @param clientType client 분류
     * @return 선택된 인증 방식
     */
    default AuthMode resolve(SecurityRequest request, SecurityContext context, SecurityBoundary boundary, ClientType clientType) {
        return resolve(request, context);
    }
}
