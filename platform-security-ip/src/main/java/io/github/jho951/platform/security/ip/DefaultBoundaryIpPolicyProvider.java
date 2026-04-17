package io.github.jho951.platform.security.ip;

import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.ResolvedSecurityProfile;
import io.github.jho951.platform.security.policy.BoundaryIpPolicyProvider;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.SecurityBoundary;
import io.github.jho951.platform.security.policy.SecurityBoundaryType;

import java.util.Objects;

/**
 * admin/internal boundary에 각각 맞는 IP guard policy를 제공하는 기본 provider다.
 */
public final class DefaultBoundaryIpPolicyProvider implements BoundaryIpPolicyProvider {
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
        this.adminEvaluator = createEvaluator(effectiveFactory, this.properties.getAdmin(), this.properties.getAdminAllowCidrs());
        this.internalEvaluator = createEvaluator(effectiveFactory, this.properties.getInternal(), this.properties.getInternalAllowCidrs());
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
        if (!properties.isEnabled() || type == SecurityBoundaryType.PUBLIC) {
            return new BoundaryAwareIpPolicy(boundary, properties, defaultEvaluator);
        }
        if (type == SecurityBoundaryType.ADMIN) {
            return new BoundaryAwareIpPolicy(boundary, properties, adminEvaluator);
        }
        if (type == SecurityBoundaryType.INTERNAL) {
            return new BoundaryAwareIpPolicy(boundary, properties, internalEvaluator);
        }
        if (profile != null && "INTERNAL_SERVICE".equals(profile.clientType())) {
            return new BoundaryAwareIpPolicy(boundary, properties, internalEvaluator);
        }
        if (profile != null && "ADMIN_CONSOLE".equals(profile.clientType())) {
            return new BoundaryAwareIpPolicy(boundary, properties, adminEvaluator);
        }
        return new BoundaryAwareIpPolicy(boundary, properties, defaultEvaluator);
    }

    private PlatformIpGuardEvaluator createEvaluator(
            PlatformIpRuleSourceFactory factory,
            PlatformSecurityProperties.BoundaryIpGuardPolicy policy,
            java.util.List<String> legacyRules
    ) {
        PlatformIpRuleSource source = factory.create(policy, legacyRules);
        return new PlatformIpGuardEvaluator(source, policy != null && policy.isDefaultAllow());
    }
}
