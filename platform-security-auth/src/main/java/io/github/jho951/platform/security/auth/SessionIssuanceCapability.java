package io.github.jho951.platform.security.auth;

/**
 * 이미 인증된 principal에 대해 session을 생성한다.
 *
 * <p>session id 생성과 저장은 설정된 auth 1계층 session store adapter에 위임한다.</p>
 */
public interface SessionIssuanceCapability {
    /**
     * principal에 대한 session id를 발급하고 저장소에 기록한다.
     *
     * @param principal 이미 인증이 끝난 principal
     * @return 발급된 session id
     */
    String issueSession(PlatformAuthenticatedPrincipal principal);
}
