package io.github.jho951.platform.security.auth;

import java.util.Objects;

/**
 * token issuer와 session issuer를 조합해 hybrid credential bundle을 발급한다.
 *
 * <p>MSA 환경에서 gateway는 access token을, browser flow는 session id를 사용할 수
 * 있도록 하나의 로그인 결과에서 두 credential을 함께 만들 때 사용한다.</p>
 */
public final class HybridIssuanceCapability {
    private final TokenIssuanceCapability tokenIssuanceCapability;
    private final SessionIssuanceCapability sessionIssuanceCapability;

    /**
     * token 발급과 session 발급 capability를 조합한다.
     *
     * @param tokenIssuanceCapability access/refresh token 발급 capability
     * @param sessionIssuanceCapability session id 발급 capability
     */
    public HybridIssuanceCapability(
            TokenIssuanceCapability tokenIssuanceCapability,
            SessionIssuanceCapability sessionIssuanceCapability
    ) {
        this.tokenIssuanceCapability = Objects.requireNonNull(tokenIssuanceCapability, "tokenIssuanceCapability");
        this.sessionIssuanceCapability = Objects.requireNonNull(sessionIssuanceCapability, "sessionIssuanceCapability");
    }

    public PlatformIssuedCredentials issue(PlatformAuthenticatedPrincipal principal) {
        Objects.requireNonNull(principal, "principal");
        return issue(new PlatformIssueTokenCommand(principal), new PlatformIssueSessionCommand(principal));
    }

    public PlatformIssuedCredentials issue(
            PlatformIssueTokenCommand tokenCommand,
            PlatformIssueSessionCommand sessionCommand
    ) {
        Objects.requireNonNull(tokenCommand, "tokenCommand");
        Objects.requireNonNull(sessionCommand, "sessionCommand");
        return new PlatformIssuedCredentials(
                tokenIssuanceCapability.issue(tokenCommand),
                sessionIssuanceCapability.issueSession(sessionCommand)
        );
    }
}
