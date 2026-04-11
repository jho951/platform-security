package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityPolicyService;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;

import java.util.Objects;

public final class SecurityIngressAdapter {
    private final SecurityPolicyService securityPolicyService;
    private final SecurityBoundaryResolver boundaryResolver;

    public SecurityIngressAdapter(SecurityPolicyService securityPolicyService, SecurityBoundaryResolver boundaryResolver) {
        this.securityPolicyService = Objects.requireNonNull(securityPolicyService, "securityPolicyService");
        this.boundaryResolver = Objects.requireNonNull(boundaryResolver, "boundaryResolver");
    }

    public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(context, "context");
        String resolvedPath = boundaryResolver.resolve(request.path());
        SecurityRequest normalizedRequest = new SecurityRequest(
                request.subject(),
                request.clientIp(),
                resolvedPath,
                request.action(),
                request.attributes(),
                request.occurredAt()
        );
        return securityPolicyService.evaluate(normalizedRequest, context);
    }

    public SecurityFailureResponse evaluateFailureResponse(SecurityRequest request, SecurityContext context) {
        return SecurityFailureResponse.from(evaluate(request, context));
    }

    public SecurityVerdict evaluate(SecurityRequest request, SecurityContextResolver contextResolver) {
        Objects.requireNonNull(contextResolver, "contextResolver");
        return evaluate(request, contextResolver.resolve(request));
    }

    public SecurityFailureResponse evaluateFailureResponse(
            SecurityRequest request,
            SecurityContextResolver contextResolver
    ) {
        Objects.requireNonNull(contextResolver, "contextResolver");
        return evaluateFailureResponse(request, contextResolver.resolve(request));
    }
}
