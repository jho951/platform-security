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
import io.github.jho951.platform.security.policy.SecurityAttributes;
import io.github.jho951.platform.security.policy.SecurityBoundaryResolver;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * web adapter가 만든 요청과 인증 context를 core security service 평가로 연결한다.
 */
public final class SecurityIngressAdapter {
    private final SecurityPolicyService securityPolicyService;
    private final SecurityBoundaryResolver boundaryResolver;

    /**
     * @param securityPolicyService 최종 정책 평가 service
     * @param boundaryResolver 요청 boundary resolver
     */
    public SecurityIngressAdapter(SecurityPolicyService securityPolicyService, SecurityBoundaryResolver boundaryResolver) {
        this.securityPolicyService = Objects.requireNonNull(securityPolicyService, "securityPolicyService");
        this.boundaryResolver = Objects.requireNonNull(boundaryResolver, "boundaryResolver");
    }

    /**
     * 요청을 평가하고 verdict만 반환한다.
     */
    public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
        return evaluateResult(request, context).verdict();
    }

    /**
     * 인증 context 해석 전에 boundary 정보를 request attribute에 반영한다.
     */
    public SecurityRequest withResolvedBoundary(SecurityRequest request) {
        Objects.requireNonNull(request, "request");
        return withResolvedBoundary(request, boundaryResolver.resolve(request));
    }

    /**
     * 요청을 평가하고 감사에 필요한 전체 결과를 반환한다.
     */
    public SecurityEvaluationResult evaluateResult(SecurityRequest request, SecurityContext context) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(context, "context");
        SecurityBoundary boundary = boundaryResolver.resolve(request);
        SecurityRequest normalizedRequest = withResolvedBoundary(request, boundary);
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
        SecurityRequest normalizedRequest = withResolvedBoundary(request);
        return evaluate(normalizedRequest, contextResolver.resolve(normalizedRequest));
    }

    public SecurityFailureResponse evaluateFailureResponse(
            SecurityRequest request,
            SecurityContextResolver contextResolver
    ) {
        Objects.requireNonNull(contextResolver, "contextResolver");
        SecurityRequest normalizedRequest = withResolvedBoundary(request);
        return evaluateFailureResponse(normalizedRequest, contextResolver.resolve(normalizedRequest));
    }

    private SecurityRequest withResolvedBoundary(SecurityRequest request, SecurityBoundary boundary) {
        String resolvedPath = normalizePath(request.path());
        Map<String, String> attributes = new LinkedHashMap<>(request.attributes());
        attributes.put(SecurityAttributes.BOUNDARY, boundary.type().name());
        attributes.put(SecurityAttributes.BOUNDARY_PATTERNS, String.join(",", boundary.patterns()));
        return new SecurityRequest(
                request.subject(),
                request.clientIp(),
                resolvedPath,
                request.action(),
                attributes,
                request.occurredAt()
        );
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
