package io.github.jho951.platform.security.auth;

import com.auth.hybrid.DefaultHybridAuthenticationProvider;
import com.auth.hybrid.HybridAuthenticationProvider;
import com.auth.session.DefaultSessionAuthenticationProvider;
import com.auth.session.IdentitySessionPrincipalMapper;
import com.auth.session.SessionPrincipalMapper;
import com.auth.session.SessionStore;
import com.auth.session.SimpleSessionStore;
import com.auth.spi.TokenService;
import com.auth.support.jwt.JwtTokenService;
import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityContextResolver;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.LinkedHashMap;
import java.util.Objects;
import java.util.Set;

public final class PlatformSecurityContextResolvers {
    private PlatformSecurityContextResolvers() {
    }

    public static SecurityContextResolver devFallback() {
        return new PlatformAuthenticationFacade();
    }

    public static SecurityContextResolver anonymous() {
        return request -> {
            Objects.requireNonNull(request, "request");
            return new SecurityContext(false, null, Set.of(), new LinkedHashMap<>(request.attributes()));
        };
    }

    public static SecurityContextResolver hybrid(TokenService tokenService, SessionStore sessionStore, SessionPrincipalMapper sessionPrincipalMapper) {
        return from(hybridAuthenticationProvider(tokenService, sessionStore, sessionPrincipalMapper));
    }

    public static SecurityContextResolver hybrid(HybridAuthenticationProvider hybridAuthenticationProvider) {
        return from(hybridAuthenticationProvider);
    }

    public static SecurityContextResolver from(HybridAuthenticationProvider hybridAuthenticationProvider) {
        return new PlatformAuthenticationFacade(hybridAuthenticationProvider);
    }

    public static HybridAuthenticationProvider hybridAuthenticationProvider(
            TokenService tokenService,
            SessionStore sessionStore,
            SessionPrincipalMapper sessionPrincipalMapper
    ) {
        Objects.requireNonNull(tokenService, "tokenService");
        Objects.requireNonNull(sessionStore, "sessionStore");
        Objects.requireNonNull(sessionPrincipalMapper, "sessionPrincipalMapper");
        return new DefaultHybridAuthenticationProvider(
                tokenService,
                new DefaultSessionAuthenticationProvider(sessionStore, sessionPrincipalMapper)
        );
    }

    public static HybridAuthenticationProvider defaultHybridAuthenticationProvider(String jwtSecret, long accessTokenTtlSeconds, long refreshTokenTtlSeconds) {
        Objects.requireNonNull(jwtSecret, "jwtSecret");
        TokenService tokenService = new JwtTokenService(jwtSecret, accessTokenTtlSeconds, refreshTokenTtlSeconds);
        SessionStore sessionStore = new SimpleSessionStore();
        SessionPrincipalMapper sessionPrincipalMapper = new IdentitySessionPrincipalMapper();
        return hybridAuthenticationProvider(tokenService, sessionStore, sessionPrincipalMapper);
    }
}
