package io.github.jho951.platform.security.auth;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.auth.AuthServerSecurityContextResolver;
import io.github.jho951.platform.security.web.SecurityContextResolver;

import java.util.Objects;

public final class PlatformAuthenticationFacade {
    private final SecurityContextResolver securityContextResolver;

    public PlatformAuthenticationFacade() {
        this.securityContextResolver = new AuthServerSecurityContextResolver();
    }

    public PlatformAuthenticationFacade(SecurityContextResolver securityContextResolver) {
        this.securityContextResolver = Objects.requireNonNull(securityContextResolver, "securityContextResolver");
    }

    public SecurityContext resolve(SecurityRequest request) {
        return securityContextResolver.resolve(request);
    }
}
