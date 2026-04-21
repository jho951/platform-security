package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;

import java.util.Objects;

/**
 * 1계층 token service에 위임해 access/refresh token을 발급하는 기본 구현이다.
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
    public PlatformTokenBundle issue(Principal principal) {
        Objects.requireNonNull(principal, "principal");
        return tokenIssuerPort.issue(principal);
    }
}
