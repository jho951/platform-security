package io.github.jho951.platform.security.auth;

import io.github.jho951.platform.security.policy.AuthMode;

/**
 * 결정된 {@link AuthMode}를 실제 인증 capability로 연결한다.
 *
 * <p>gateway, auth-server, internal service가 같은 mode 값을 공유하더라도 실제
 * credential 검증 방식은 서비스 구성이 제공한 capability가 담당한다.</p>
 */
public interface AuthenticationCapabilityResolver {
    /**
     * 인증 mode에 맞는 capability를 반환한다.
     *
     * @param authMode 요청에 적용할 인증 mode
     * @return mode를 처리하는 capability
     */
    AuthenticationCapability resolve(AuthMode authMode);

    /**
     * internal service 경로 여부까지 고려해 capability를 반환한다.
     *
     * @param authMode 요청에 적용할 인증 mode
     * @param internalService internal service 요청이면 true
     * @return 요청을 처리할 capability
     */
    default AuthenticationCapability resolve(AuthMode authMode, boolean internalService) {
        return resolve(authMode);
    }
}
