package io.github.jho951.platform.security.auth;

/**
 * 이미 인증된 principal에 대해 platform token을 발급한다.
 *
 * <p>로그인 성공 여부와 발급 시점은 서비스가 결정한다. 이 capability는 설정된
 * auth 1계층 token service에 위임하고 결과를 호출자가 쓰기 쉬운 형태로 묶는다.</p>
 */
public interface TokenIssuanceCapability {
    /**
     * principal에 대한 token 묶음을 발급한다.
     *
     * @param principal 이미 인증이 끝난 principal
     * @return access token, refresh token, 필요 시 session id를 담은 bundle
     */
    PlatformTokenBundle issue(PlatformAuthenticatedPrincipal principal);
}
