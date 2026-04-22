package io.github.jho951.platform.security.auth;

/**
 * 이미 인증된 principal에 대해 platform-owned session view를 생성한다.
 *
 * <p>session id 생성과 저장은 설정된 auth 1계층 session store adapter에 위임한다.</p>
 */
public interface SessionIssuanceCapability {
    /**
     * session 발급 command를 실행하고 저장소에 기록한다.
     *
     * @param command 발급에 필요한 runtime 입력
     * @return 발급된 session view
     */
    PlatformSessionView issueSession(PlatformIssueSessionCommand command);

    default PlatformSessionView issueSession(PlatformAuthenticatedPrincipal principal) {
        return issueSession(new PlatformIssueSessionCommand(principal));
    }
}
