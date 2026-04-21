package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
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
    public PlatformTokenBundle issue(Principal principal) {
        Objects.requireNonNull(principal, "principal");
        return new PlatformTokenBundle(
                tokenService.issueAccessToken(principal),
                tokenService.issueRefreshToken(principal),
                null
        );
    }
}
