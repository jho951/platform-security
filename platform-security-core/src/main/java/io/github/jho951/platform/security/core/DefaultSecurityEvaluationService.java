package io.github.jho951.platform.security.core;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityEvaluationContext;
import io.github.jho951.platform.security.api.SecurityEvaluationResult;
import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.SecurityPolicyService;
import io.github.jho951.platform.security.api.ResolvedSecurityProfile;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.api.SecurityEvaluationService;
import io.github.jho951.platform.security.policy.AuthenticationModeResolver;
import io.github.jho951.platform.security.policy.AuthMode;
import io.github.jho951.platform.security.policy.BoundaryIpPolicyProvider;
import io.github.jho951.platform.security.policy.BoundaryRateLimitPolicyProvider;
import io.github.jho951.platform.security.policy.ClientType;
import io.github.jho951.platform.security.policy.ClientTypeResolver;
import io.github.jho951.platform.security.policy.DefaultPlatformPrincipalFactory;
import io.github.jho951.platform.security.policy.PlatformPrincipalFactory;
import io.github.jho951.platform.security.policy.SecurityAttributes;
import io.github.jho951.platform.security.policy.SecurityBoundary;
import io.github.jho951.platform.security.policy.SecurityBoundaryResolver;
import io.github.jho951.platform.security.policy.SecurityBoundaryType;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * boundary, client type, auth mode를 해석한 뒤 기본 보안 policy chain을 실행하는 core 평가 서비스다.
 * <p>
 * 기본 chain은 인증 필수 여부, IP guard, rate limit, 추가 등록 policy 순서로 평가한다.
 * 첫 deny verdict가 나오면 즉시 평가를 중단한다.
 * </p>
 */
public class DefaultSecurityEvaluationService implements SecurityEvaluationService, SecurityPolicyService {
    private final List<SecurityPolicy> policies;
    private final SecurityBoundaryResolver boundaryResolver;
    private final ClientTypeResolver clientTypeResolver;
    private final AuthenticationModeResolver authenticationModeResolver;
    private final BoundaryIpPolicyProvider boundaryIpPolicyProvider;
    private final BoundaryRateLimitPolicyProvider boundaryRateLimitPolicyProvider;
    private final PlatformPrincipalFactory principalFactory;

	private SecurityEvaluationResult evaluateSelectionMode(SecurityRequest request, SecurityContext context) {
		SecurityBoundary boundary = resolveBoundary(request);
		ClientType clientType = clientTypeResolver.resolve(request, context, boundary);
		AuthMode authMode = authenticationModeResolver.resolve(request, context, boundary, clientType);
		ResolvedSecurityProfile profile = new ResolvedSecurityProfile(
			boundary.type().name(),
			boundary.patterns(),
			clientType.name(),
			authMode.name()
		);
		String principal = principalFactory.createPrincipal(context);

		Map<String, String> attributes = new LinkedHashMap<>(request.attributes());
		attributes.put(SecurityAttributes.BOUNDARY, profile.boundaryType());
		attributes.put(SecurityAttributes.BOUNDARY_PATTERNS, String.join(",", profile.boundaryPatterns()));
		attributes.put(SecurityAttributes.CLIENT_TYPE, profile.clientType());
		attributes.put(SecurityAttributes.AUTH_MODE, profile.authMode());
		if (principal != null) attributes.put(SecurityAttributes.PRINCIPAL, principal);

		SecurityRequest resolvedRequest = new SecurityRequest(
			principal != null ? principal : request.subject(),
			request.clientIp(),
			request.path(),
			request.action(),
			attributes,
			request.occurredAt()
		);

		List<SecurityPolicy> chain = new ArrayList<>();
		chain.add(new io.github.jho951.platform.security.core.policy.RequireAuthenticatedPolicy());
		chain.add(boundaryIpPolicyProvider.resolve(boundary, profile));
		chain.add(boundaryRateLimitPolicyProvider.resolve(boundary, profile));
		chain.addAll(policies);

		SecurityVerdict verdict = SecurityVerdict.allow("selection", "all selected policies passed");
		for (SecurityPolicy policy : chain) {
			verdict = policy.evaluate(resolvedRequest, context);
			if (!verdict.allowed()) break;
		}

		return new SecurityEvaluationResult(new SecurityEvaluationContext(resolvedRequest, context, profile), verdict);
	}

	private SecurityVerdict evaluatePolicyList(SecurityRequest request, SecurityContext context) {
		for (SecurityPolicy policy : policies) {
			SecurityVerdict verdict = policy.evaluate(request, context);
			if (!verdict.allowed()) return verdict;
		}
		return SecurityVerdict.allow("default", "all policies passed");
	}

	private SecurityBoundary resolveBoundary(SecurityRequest request) {
		String boundaryName = request.attributes().get(SecurityAttributes.BOUNDARY);
		if (boundaryName != null && !boundaryName.isBlank()) {
			try {
				return new SecurityBoundary(SecurityBoundaryType.valueOf(boundaryName.trim().toUpperCase(Locale.ROOT)), List.of());
			} catch (IllegalArgumentException ignored) {}
		}
		return boundaryResolver.resolve(request);
	}

	private ResolvedSecurityProfile resolveFallbackProfile(SecurityRequest request, SecurityContext context) {
		SecurityBoundary boundary = resolveFallbackBoundary(request);
		ClientType clientType = resolveFallbackClientType(request, context, boundary);
		AuthMode authMode = resolveFallbackAuthMode(request, context, boundary);
		return new ResolvedSecurityProfile(
			boundary.type().name(),
			boundary.patterns(),
			clientType.name(),
			authMode.name()
		);
	}

	private SecurityBoundary resolveFallbackBoundary(SecurityRequest request) {
		String boundaryName = request.attributes().get(SecurityAttributes.BOUNDARY);
		if (boundaryName != null && !boundaryName.isBlank()) {
			try {
				return new SecurityBoundary(SecurityBoundaryType.valueOf(boundaryName.trim().toUpperCase(Locale.ROOT)), List.of());
			} catch (IllegalArgumentException ignored) {}
		}
		return new SecurityBoundary(SecurityBoundaryType.PROTECTED, List.of());
	}

	private ClientType resolveFallbackClientType(SecurityRequest request, SecurityContext context, SecurityBoundary boundary) {
		String boundaryType = boundary.type().name();
		if (SecurityBoundaryType.INTERNAL.name().equals(boundaryType)) return ClientType.INTERNAL_SERVICE;
		if (SecurityBoundaryType.ADMIN.name().equals(boundaryType)) return ClientType.ADMIN_CONSOLE;
		if (request.attributes().containsKey("auth.sessionId")) return ClientType.BROWSER;
		if (request.attributes().containsKey("auth.accessToken") || context.authenticated()) return ClientType.EXTERNAL_API;
		return ClientType.EXTERNAL_API;
	}

	private AuthMode resolveFallbackAuthMode(SecurityRequest request, SecurityContext context, SecurityBoundary boundary) {
		if (SecurityBoundaryType.PUBLIC.name().equals(boundary.type().name())) return AuthMode.NONE;
		String sessionId = trimToNull(request.attributes().get("auth.sessionId"));
		String accessToken = trimToNull(request.attributes().get("auth.accessToken"));
		if (SecurityBoundaryType.INTERNAL.name().equals(boundary.type().name())) return AuthMode.HYBRID;
		if (sessionId != null && accessToken != null) return AuthMode.HYBRID;
		if (sessionId != null) return AuthMode.SESSION;
		if (accessToken != null) return AuthMode.JWT;
		return context.authenticated() ? AuthMode.HYBRID : AuthMode.NONE;
	}

	private String trimToNull(String value) {
		if (value == null) return null;
		String trimmed = value.trim();
		return trimmed.isEmpty() ? null : trimmed;
	}

	private boolean isSelectionMode() {
		return boundaryResolver != null
			&& clientTypeResolver != null
			&& authenticationModeResolver != null
			&& boundaryIpPolicyProvider != null
			&& boundaryRateLimitPolicyProvider != null;
	}

    public DefaultSecurityEvaluationService(List<SecurityPolicy> policies) {
        this.policies = policies == null ? List.of() : List.copyOf(policies);
        this.boundaryResolver = null;
        this.clientTypeResolver = null;
        this.authenticationModeResolver = null;
        this.boundaryIpPolicyProvider = null;
        this.boundaryRateLimitPolicyProvider = null;
        this.principalFactory = new DefaultPlatformPrincipalFactory();
    }

    public DefaultSecurityEvaluationService(
            SecurityBoundaryResolver boundaryResolver,
            ClientTypeResolver clientTypeResolver,
            AuthenticationModeResolver authenticationModeResolver,
            BoundaryIpPolicyProvider boundaryIpPolicyProvider,
            BoundaryRateLimitPolicyProvider boundaryRateLimitPolicyProvider,
            PlatformPrincipalFactory principalFactory
    ) {
        this.policies = List.of();
        this.boundaryResolver = Objects.requireNonNull(boundaryResolver, "boundaryResolver");
        this.clientTypeResolver = Objects.requireNonNull(clientTypeResolver, "clientTypeResolver");
        this.authenticationModeResolver = Objects.requireNonNull(authenticationModeResolver, "authenticationModeResolver");
        this.boundaryIpPolicyProvider = Objects.requireNonNull(boundaryIpPolicyProvider, "boundaryIpPolicyProvider");
        this.boundaryRateLimitPolicyProvider = Objects.requireNonNull(boundaryRateLimitPolicyProvider, "boundaryRateLimitPolicyProvider");
        this.principalFactory = principalFactory == null ? new DefaultPlatformPrincipalFactory() : principalFactory;
    }

    @Override
    public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
        return evaluateResult(request, context).verdict();
    }

    @Override
    public SecurityEvaluationResult evaluateResult(SecurityRequest request, SecurityContext context) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(context, "context");

        if (isSelectionMode()) return evaluateSelectionMode(request, context);

        SecurityVerdict verdict = evaluatePolicyList(request, context);
        return new SecurityEvaluationResult(
                new SecurityEvaluationContext(request, context, resolveFallbackProfile(request, context)),
                verdict
        );
    }
}
