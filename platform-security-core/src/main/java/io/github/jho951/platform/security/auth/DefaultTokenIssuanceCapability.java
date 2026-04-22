package io.github.jho951.platform.security.auth;

import java.util.Objects;

/**
 * token issuer port에 위임해 access/refresh token을 발급하는 기본 구현이다.
 */
public final class DefaultTokenIssuanceCapability implements TokenIssuanceCapability {
    private final PlatformTokenIssuerPort tokenIssuerPort;

    /**
     * token service와 issuer capability를 연결한다.
     *
     * @param tokenIssuerPort access/refresh token 발급 port
     */
    public DefaultTokenIssuanceCapability(PlatformTokenIssuerPort tokenIssuerPort) {
        this.tokenIssuerPort = Objects.requireNonNull(tokenIssuerPort, "tokenIssuerPort");
    }

    @Override
    public PlatformIssuedToken issue(PlatformIssueTokenCommand command) {
        Objects.requireNonNull(command, "command");
        return tokenIssuerPort.issue(command);
    }
}
