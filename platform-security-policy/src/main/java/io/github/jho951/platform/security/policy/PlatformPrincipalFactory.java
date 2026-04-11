package io.github.jho951.platform.security.policy;

import io.github.jho951.platform.security.api.SecurityContext;

public interface PlatformPrincipalFactory {
    String createPrincipal(SecurityContext context);
}
