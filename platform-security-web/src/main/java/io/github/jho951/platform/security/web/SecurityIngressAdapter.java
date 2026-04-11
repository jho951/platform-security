package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityContextResolver;
import io.github.jho951.platform.security.api.SecurityEvaluationContext;
import io.github.jho951.platform.security.api.SecurityEvaluationResult;
import io.github.jho951.platform.security.api.SecurityEvaluationService;
import io.github.jho951.platform.security.api.SecurityPolicyService;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.api.ResolvedSecurityProfile;
import io.github.jho951.platform.security.policy.AuthMode;
import io.github.jho951.platform.security.policy.ClientType;
import io.github.jho951.platform.security.policy.SecurityBoundary;
import io.github.jho951.platform.security.policy.SecurityBoundaryResolver;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public final class SecurityIngressAdapter {
    private final SecurityPolicyService securityPolicyService;
    private final SecurityBoundaryResolver boundaryResolver;

    public SecurityIngressAdapter(SecurityPolicyService securityPolicyService, SecurityBoundaryResolver boundaryResolver) {
        this.securityPolicyService = Objects.requireNonNull(securityPolicyService, "securityPolicyService");
        this.boundaryResolver = Objects.requireNonNull(boundaryResolver, "boundaryResolver");
    }

    public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
        return evaluateResult(request, context).verdict();
    }

    public SecurityEvaluationResult evaluateResult(SecurityRequest request, SecurityContext context) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(context, "context");
        SecurityBoundary boundary = boundaryResolver.resolve(request);
        String resolvedPath = normalizePath(request.path());
        Map<String, String> attributes = new LinkedHashMap<>(request.attributes());
        attributes.put("security.boundary", boundary.type().name());
        attributes.put("security.boundary.patterns", String.join(",", boundary.patterns()));
        SecurityRequest normalizedRequest = new SecurityRequest(
                request.subject(),
                request.clientIp(),
                resolvedPath,
                request.action(),
                attributes,
                request.occurredAt()
        );
        if (securityPolicyService instanceof SecurityEvaluationService evaluationService) {
            return evaluationService.evaluateResult(normalizedRequest, context);
        }
        SecurityVerdict verdict = securityPolicyService.evaluate(normalizedRequest, context);
        return new SecurityEvaluationResult(
                new SecurityEvaluationContext(normalizedRequest, context, resolveFallbackProfile(normalizedRequest, context, boundary)),
                verdict
        );
    }

    public SecurityFailureResponse evaluateFailureResponse(SecurityRequest request, SecurityContext context) {
        return SecurityFailureResponse.from(evaluateResult(request, context).verdict());
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

    private String normalizePath(String requestPath) {
        Objects.requireNonNull(requestPath, "requestPath");
        String normalized = requestPath.trim();
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("requestPath must not be blank");
        }
        return normalized.startsWith("/") ? normalized : "/" + normalized;
    }

    private ResolvedSecurityProfile resolveFallbackProfile(SecurityRequest request, SecurityContext context, SecurityBoundary boundary) {
        ClientType clientType;
        if (boundary.type().name().equals("INTERNAL")) {
            clientType = ClientType.INTERNAL_SERVICE;
        } else if (boundary.type().name().equals("ADMIN")) {
            clientType = ClientType.ADMIN_CONSOLE;
        } else if (request.attributes().containsKey("auth.sessionId")) {
            clientType = ClientType.BROWSER;
        } else {
            clientType = ClientType.EXTERNAL_API;
        }

        AuthMode authMode;
        if (boundary.type().name().equals("PUBLIC")) {
            authMode = AuthMode.NONE;
        } else if (boundary.type().name().equals("INTERNAL")) {
            authMode = AuthMode.HYBRID;
        } else if (request.attributes().containsKey("auth.sessionId") && request.attributes().containsKey("auth.accessToken")) {
            authMode = AuthMode.HYBRID;
        } else if (request.attributes().containsKey("auth.sessionId")) {
            authMode = AuthMode.SESSION;
        } else if (request.attributes().containsKey("auth.accessToken")) {
            authMode = AuthMode.JWT;
        } else if (context.authenticated()) {
            authMode = AuthMode.HYBRID;
        } else {
            authMode = AuthMode.NONE;
        }

        return new ResolvedSecurityProfile(
                boundary.type().name(),
                boundary.patterns(),
                clientType.name(),
                authMode.name()
        );
    }
}
