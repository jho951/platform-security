package io.github.jho951.platform.security.policy;

import io.github.jho951.platform.security.api.SecurityContext;

import java.util.Objects;

public final class DefaultPlatformPrincipalFactory implements PlatformPrincipalFactory {
    @Override
    public String createPrincipal(SecurityContext context) {
        Objects.requireNonNull(context, "context");
        return context.principal();
    }
}
