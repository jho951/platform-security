package io.github.jho951.platform.security.core;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityEvaluationResult;
import io.github.jho951.platform.security.api.SecurityEvaluationService;
import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.SecurityPolicyService;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.policy.AuthenticationModeResolver;
import io.github.jho951.platform.security.policy.BoundaryIpPolicyProvider;
import io.github.jho951.platform.security.policy.BoundaryRateLimitPolicyProvider;
import io.github.jho951.platform.security.policy.ClientTypeResolver;
import io.github.jho951.platform.security.policy.PlatformPrincipalFactory;
import io.github.jho951.platform.security.policy.SecurityBoundaryResolver;

import java.util.List;
import java.util.Objects;

/**
 * {@link DefaultSecurityEvaluationService}를 감싼 기본 facade 구현이다.
 *
 * <p>legacy policy list 방식과 selection-mode 평가 방식을 모두 지원한다.</p>
 */
public final class DefaultSecurityPolicyService implements SecurityPolicyService, SecurityEvaluationService {
    private final DefaultSecurityEvaluationService delegate;

    public DefaultSecurityPolicyService(List<SecurityPolicy> policies) {
        this.delegate = new DefaultSecurityEvaluationService(policies);
    }

    public DefaultSecurityPolicyService(
            SecurityBoundaryResolver boundaryResolver,
            ClientTypeResolver clientTypeResolver,
            AuthenticationModeResolver authenticationModeResolver,
            BoundaryIpPolicyProvider boundaryIpPolicyProvider,
            BoundaryRateLimitPolicyProvider boundaryRateLimitPolicyProvider,
            PlatformPrincipalFactory principalFactory
    ) {
        this(
                boundaryResolver,
                clientTypeResolver,
                authenticationModeResolver,
                boundaryIpPolicyProvider,
                boundaryRateLimitPolicyProvider,
                principalFactory,
                List.of()
        );
    }

    public DefaultSecurityPolicyService(
            SecurityBoundaryResolver boundaryResolver,
            ClientTypeResolver clientTypeResolver,
            AuthenticationModeResolver authenticationModeResolver,
            BoundaryIpPolicyProvider boundaryIpPolicyProvider,
            BoundaryRateLimitPolicyProvider boundaryRateLimitPolicyProvider,
            PlatformPrincipalFactory principalFactory,
            List<SecurityPolicy> policies
    ) {
        this.delegate = new DefaultSecurityEvaluationService(
                boundaryResolver,
                clientTypeResolver,
                authenticationModeResolver,
                boundaryIpPolicyProvider,
                boundaryRateLimitPolicyProvider,
                principalFactory,
                policies
        );
    }

    @Override
    public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(context, "context");
        return delegate.evaluate(request, context);
    }

    @Override
    public SecurityEvaluationResult evaluateResult(SecurityRequest request, SecurityContext context) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(context, "context");
        return delegate.evaluateResult(request, context);
    }
}
