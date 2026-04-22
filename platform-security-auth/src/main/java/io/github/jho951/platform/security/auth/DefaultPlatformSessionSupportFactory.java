package io.github.jho951.platform.security.auth;

import com.auth.hybrid.DefaultHybridAuthenticationProvider;
import com.auth.hybrid.HybridAuthenticationProvider;
import com.auth.session.DefaultSessionAuthenticationProvider;
import com.auth.session.SessionPrincipalMapper;
import com.auth.session.SessionStore;
import com.auth.spi.TokenService;

import java.util.Objects;

/**
 * auth 1계층 bean graph를 platform session support로 숨기는 기본 factory다.
 */
public final class DefaultPlatformSessionSupportFactory implements PlatformSessionSupportFactory {
    private final HybridAuthenticationProvider hybridAuthenticationProvider;

    public DefaultPlatformSessionSupportFactory(HybridAuthenticationProvider hybridAuthenticationProvider) {
        this.hybridAuthenticationProvider = Objects.requireNonNull(hybridAuthenticationProvider, "hybridAuthenticationProvider");
    }

    public DefaultPlatformSessionSupportFactory(
            TokenService tokenService,
            SessionStore sessionStore,
            SessionPrincipalMapper sessionPrincipalMapper
    ) {
        this(new DefaultHybridAuthenticationProvider(
                Objects.requireNonNull(tokenService, "tokenService"),
                new DefaultSessionAuthenticationProvider(
                        Objects.requireNonNull(sessionStore, "sessionStore"),
                        Objects.requireNonNull(sessionPrincipalMapper, "sessionPrincipalMapper")
                )
        ));
    }

    @Override
    public PlatformSessionSupport create() {
        return new DefaultPlatformSessionSupport(hybridAuthenticationProvider);
    }
}
