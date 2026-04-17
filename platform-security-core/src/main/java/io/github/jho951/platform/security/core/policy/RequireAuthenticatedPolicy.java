package io.github.jho951.platform.security.core.policy;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.policy.SecurityAttributes;

/**
 * PUBLIC boundary나 auth mode NONE이 아닌 요청에 인증을 요구하는 기본 policy다.
 */
public final class RequireAuthenticatedPolicy implements SecurityPolicy {
    @Override
    public String name() {
        return "auth";
    }

    @Override
    public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
        String boundary = request.attributes().get(SecurityAttributes.BOUNDARY);
        if ("PUBLIC".equalsIgnoreCase(boundary)) {
            return SecurityVerdict.allow(name(), "public boundary");
        }
        String authMode = request.attributes().get(SecurityAttributes.AUTH_MODE);
        if ("NONE".equalsIgnoreCase(authMode)) {
            return SecurityVerdict.allow(name(), "authentication disabled");
        }
        if (context.authenticated()){
			return SecurityVerdict.allow(name(), "authenticated");
		}
        return SecurityVerdict.deny(name(), "authentication required");
    }
}
