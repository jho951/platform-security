package io.github.jho951.platform.security.core.policy;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;

public final class RequireAuthenticatedPolicy implements SecurityPolicy {
    @Override
    public String name() {
        return "auth";
    }

    @Override
    public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
        if (context.authenticated()) return SecurityVerdict.allow(name(), "authenticated");
        return SecurityVerdict.deny(name(), "authentication required");
    }
}
