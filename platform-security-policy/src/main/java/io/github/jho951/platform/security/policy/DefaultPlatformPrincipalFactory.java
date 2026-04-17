package io.github.jho951.platform.security.policy;

import io.github.jho951.platform.security.api.SecurityContext;

import java.util.Objects;

/**
 * {@link SecurityContext#principal()} 값을 그대로 platform principal로 사용하는 기본 구현이다.
 */
public final class DefaultPlatformPrincipalFactory implements PlatformPrincipalFactory {
    @Override
    public String createPrincipal(SecurityContext context) {
        Objects.requireNonNull(context, "context");
        return context.principal();
    }
}
