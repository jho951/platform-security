package io.github.jho951.platform.security.ip;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.SecurityBoundary;
import io.github.jho951.platform.security.policy.SecurityBoundaryType;
import com.ipguard.core.decision.Decision;

import java.util.Locale;
import java.util.Objects;

/**
 * 요청 boundary에 맞는 IP guard evaluator를 실행하는 보안 policy다.
 */
public final class BoundaryAwareIpPolicy implements SecurityPolicy {
    private final SecurityBoundary boundary;
    private final PlatformSecurityProperties.IpGuardProperties properties;
    private final PlatformIpGuardEvaluator evaluator;
    private final String policyBasis;
    private final String clientType;
    private final boolean enforcePublicBoundary;

    public BoundaryAwareIpPolicy(
            SecurityBoundary boundary,
            PlatformSecurityProperties.IpGuardProperties properties,
            PlatformIpGuardEvaluator evaluator
    ) {
        this(boundary, properties, evaluator, "PATH", null, false);
    }

    public BoundaryAwareIpPolicy(
            SecurityBoundary boundary,
            PlatformSecurityProperties.IpGuardProperties properties,
            PlatformIpGuardEvaluator evaluator,
            String policyBasis,
            String clientType,
            boolean enforcePublicBoundary
    ) {
        this.boundary = Objects.requireNonNull(boundary, "boundary");
        this.properties = properties == null ? new PlatformSecurityProperties.IpGuardProperties() : properties;
        this.evaluator = Objects.requireNonNull(evaluator, "evaluator");
        this.policyBasis = normalize(policyBasis, "PATH");
        this.clientType = normalize(clientType, "UNKNOWN");
        this.enforcePublicBoundary = enforcePublicBoundary;
    }

    @Override
    public String name() {
        return "ip-guard";
    }

    @Override
    public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
        Objects.requireNonNull(request, "request");
        if (!properties.isEnabled()) {
            return SecurityVerdict.allow(name(), "ip policy skipped: disabled");
        }
        if (boundary.type() == SecurityBoundaryType.PUBLIC && !enforcePublicBoundary) {
            return SecurityVerdict.allow(name(), "ip policy skipped: boundary=PUBLIC");
        }
        Decision decision = evaluator.decide(request.clientIp());
        String reason = withSelectionContext(decision.reason());
        if (decision.allowed()) {
            return SecurityVerdict.allow(name(), reason);
        }
        return SecurityVerdict.deny(name(), reason);
    }

    private String withSelectionContext(String reason) {
        String context = "boundary=" + boundary.type()
                + ", clientType=" + clientType
                + ", policyBasis=" + policyBasis;
        String trimmed = reason == null ? "" : reason.trim();
        if (trimmed.isEmpty()) {
            return context;
        }
        return trimmed + " (" + context + ")";
    }

    private String normalize(String value, String fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        return value.trim().toUpperCase(Locale.ROOT);
    }
}
