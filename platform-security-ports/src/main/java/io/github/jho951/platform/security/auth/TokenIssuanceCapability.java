package io.github.jho951.platform.security.auth;

/**
 * 이미 인증된 principal에 대해 platform-owned token view를 발급한다.
 *
 * <p>로그인 성공 여부와 발급 시점은 서비스가 결정한다. 이 capability는 설정된
 * auth adapter port에 위임하고 결과를 호출자가 쓰기 쉬운 runtime view로 반환한다.</p>
 */
public interface TokenIssuanceCapability {
    /**
     * token 발급 command를 실행한다.
     *
     * @param command 발급에 필요한 runtime 입력
     * @return 발급된 access/refresh token view
     */
    PlatformIssuedToken issue(PlatformIssueTokenCommand command);

    default PlatformIssuedToken issue(PlatformAuthenticatedPrincipal principal) {
        return issue(new PlatformIssueTokenCommand(principal));
    }
}
