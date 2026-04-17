package io.github.jho951.platform.security.ip;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.SecurityBoundary;
import io.github.jho951.platform.security.policy.SecurityBoundaryType;
import com.ipguard.core.decision.Decision;

import java.util.Objects;

/**
 * 요청 boundary에 맞는 IP guard evaluator를 실행하는 보안 policy다.
 */
public final class BoundaryAwareIpPolicy implements SecurityPolicy {
    private final SecurityBoundary boundary;
    private final PlatformSecurityProperties.IpGuardProperties properties;
    private final PlatformIpGuardEvaluator evaluator;

    public BoundaryAwareIpPolicy(
            SecurityBoundary boundary,
            PlatformSecurityProperties.IpGuardProperties properties,
            PlatformIpGuardEvaluator evaluator
    ) {
        this.boundary = Objects.requireNonNull(boundary, "boundary");
        this.properties = properties == null ? new PlatformSecurityProperties.IpGuardProperties() : properties;
        this.evaluator = Objects.requireNonNull(evaluator, "evaluator");
    }

    @Override
    public String name() {
        return "ip-guard";
    }

    @Override
    public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
        Objects.requireNonNull(request, "request");
        if (!properties.isEnabled() || boundary.type() == SecurityBoundaryType.PUBLIC) {
            return SecurityVerdict.allow(name(), "ip policy disabled");
        }
        Decision decision = evaluator.decide(request.clientIp());
        if (decision.allowed()) return SecurityVerdict.allow(name(), decision.reason());
        return SecurityVerdict.deny(name(), decision.reason());
    }
}
