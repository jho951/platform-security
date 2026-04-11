package io.github.jho951.platform.security.policy;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.ResolvedSecurityProfile;

public interface RateLimitKeyResolver {
    String resolve(SecurityRequest request, SecurityContext context);

    default String resolve(SecurityRequest request, SecurityContext context, ResolvedSecurityProfile profile) {
        return resolve(request, context);
    }
}
