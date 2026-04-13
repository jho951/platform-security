package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.spi.TokenService;

import java.util.Objects;

public final class DefaultTokenIssuanceCapability implements TokenIssuanceCapability {
    private final TokenService tokenService;

    public DefaultTokenIssuanceCapability(TokenService tokenService) {
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
