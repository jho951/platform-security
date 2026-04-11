package io.github.jho951.platform.security.core;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.SecurityPolicyService;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;

import java.util.List;
import java.util.Objects;

public final class DefaultSecurityPolicyService implements SecurityPolicyService {
    private final List<SecurityPolicy> policies;

    public DefaultSecurityPolicyService(List<SecurityPolicy> policies) {
        this.policies = policies == null ? List.of() : List.copyOf(policies);
    }

    @Override
    public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(context, "context");

        for (SecurityPolicy policy : policies) {
            SecurityVerdict verdict = policy.evaluate(request, context);
            if (!verdict.allowed()) return verdict;
        }
        return SecurityVerdict.allow("default", "all policies passed");
    }
}
