package io.github.jho951.platform.security.auth;

import com.auth.spi.TokenService;

import java.util.Objects;

/**
 * 1계층 TokenService를 platform token issuer port로 감싼다.
 */
public final class TokenServicePlatformTokenIssuerPort implements PlatformTokenIssuerPort {
    private final TokenService tokenService;

    public TokenServicePlatformTokenIssuerPort(TokenService tokenService) {
        this.tokenService = Objects.requireNonNull(tokenService, "tokenService");
    }

    @Override
    public PlatformTokenBundle issue(PlatformAuthenticatedPrincipal principal) {
        Objects.requireNonNull(principal, "principal");
        com.auth.api.model.Principal authPrincipal = AuthPrincipalAdapters.toAuth(principal);
        return new PlatformTokenBundle(
                tokenService.issueAccessToken(authPrincipal),
                tokenService.issueRefreshToken(authPrincipal),
                null
        );
    }
}
