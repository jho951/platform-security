package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.spi.TokenService;

import java.util.Objects;

/**
 * 1계층 token service에 위임해 access/refresh token을 발급하는 기본 구현이다.
 */
public final class DefaultTokenIssuanceCapability implements TokenIssuanceCapability {
    private final TokenService tokenService;

    /**
     * token service와 issuer capability를 연결한다.
     *
     * @param tokenService access/refresh token 발급 service
     */
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
