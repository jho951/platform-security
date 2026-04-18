package io.github.jho951.platform.security.ip;

import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.ResolvedSecurityProfile;
import io.github.jho951.platform.security.policy.BoundaryIpPolicyProvider;
import io.github.jho951.platform.security.policy.ClientType;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.SecurityBoundary;
import io.github.jho951.platform.security.policy.SecurityBoundaryType;

import java.util.Objects;

/**
 * admin/internal boundary에 각각 맞는 IP guard policy를 제공하는 기본 provider다.
 */
public final class DefaultBoundaryIpPolicyProvider implements BoundaryIpPolicyProvider {
    /**
     * IP guard는 먼저 resolved client type을 보고, 그 다음 path boundary를 방어선으로 사용한다.
     */
    public static final boolean CLIENT_TYPE_OVERRIDE = true;

    private final PlatformSecurityProperties.IpGuardProperties properties;
    private final PlatformIpGuardEvaluator adminEvaluator;
    private final PlatformIpGuardEvaluator internalEvaluator;
    private final PlatformIpGuardEvaluator defaultEvaluator;

    public DefaultBoundaryIpPolicyProvider(PlatformSecurityProperties.IpGuardProperties properties) {
        this(properties, new DefaultPlatformIpRuleSourceFactory());
    }

    public DefaultBoundaryIpPolicyProvider(
            PlatformSecurityProperties.IpGuardProperties properties,
            PlatformIpRuleSourceFactory ruleSourceFactory
    ) {
        this.properties = properties == null ? new PlatformSecurityProperties.IpGuardProperties() : properties;
        PlatformIpRuleSourceFactory effectiveFactory = ruleSourceFactory == null
                ? new DefaultPlatformIpRuleSourceFactory()
                : ruleSourceFactory;
        this.adminEvaluator = createEvaluator(effectiveFactory, this.properties.getAdmin());
        this.internalEvaluator = createEvaluator(effectiveFactory, this.properties.getInternal());
        this.defaultEvaluator = new PlatformIpGuardEvaluator(new InlinePlatformIpRuleSource(null), true);
    }

    @Override
    public SecurityPolicy resolve(SecurityBoundary boundary) {
        return resolve(boundary, null);
    }

    @Override
    public SecurityPolicy resolve(SecurityBoundary boundary, ResolvedSecurityProfile profile) {
        Objects.requireNonNull(boundary, "boundary");
        SecurityBoundaryType type = boundary.type();
        if (!properties.isEnabled()) {
            return policy(boundary, defaultEvaluator, "DISABLED", profile, false);
        }

        if (CLIENT_TYPE_OVERRIDE && isClientType(profile, ClientType.INTERNAL_SERVICE)) {
            return policy(boundary, internalEvaluator, "CLIENT_TYPE", profile, true);
        }

        if (CLIENT_TYPE_OVERRIDE && isClientType(profile, ClientType.ADMIN_CONSOLE)) {
            return policy(boundary, adminEvaluator, "CLIENT_TYPE", profile, true);
        }

        if (type == SecurityBoundaryType.ADMIN) {
            return policy(boundary, adminEvaluator, "PATH", profile, false);
        }

        if (type == SecurityBoundaryType.INTERNAL) {
            return policy(boundary, internalEvaluator, "PATH", profile, false);
        }

        return policy(boundary, defaultEvaluator, "NONE", profile, false);
    }

    private PlatformIpGuardEvaluator createEvaluator(
            PlatformIpRuleSourceFactory factory,
            PlatformSecurityProperties.BoundaryIpGuardPolicy policy
    ) {
        PlatformIpRuleSource source = factory.create(policy);
        return new PlatformIpGuardEvaluator(source, policy != null && policy.isDefaultAllow());
    }

    private BoundaryAwareIpPolicy policy(
            SecurityBoundary boundary,
            PlatformIpGuardEvaluator evaluator,
            String basis,
            ResolvedSecurityProfile profile,
            boolean enforcePublicBoundary
    ) {
        return new BoundaryAwareIpPolicy(
                boundary,
                properties,
                evaluator,
                basis,
                profile == null ? null : profile.clientType(),
                enforcePublicBoundary
        );
    }

    private boolean isClientType(ResolvedSecurityProfile profile, ClientType clientType) {
        return profile != null && clientType.name().equals(profile.clientType());
    }
}
