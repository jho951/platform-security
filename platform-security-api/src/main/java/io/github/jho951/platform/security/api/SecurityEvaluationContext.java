package io.github.jho951.platform.security.api;

import java.util.Objects;

public record SecurityEvaluationContext(
        SecurityRequest request,
        SecurityContext securityContext,
        ResolvedSecurityProfile profile
) {
    public SecurityEvaluationContext {
        request = Objects.requireNonNull(request, "request");
        securityContext = Objects.requireNonNull(securityContext, "securityContext");
        profile = Objects.requireNonNull(profile, "profile");
    }
}
