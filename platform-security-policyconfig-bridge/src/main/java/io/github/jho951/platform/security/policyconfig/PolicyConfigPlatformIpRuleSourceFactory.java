package io.github.jho951.platform.security.policyconfig;

import io.github.jho951.platform.policy.api.PolicyConfigSource;
import io.github.jho951.platform.security.autoconfigure.SpringPlatformIpRuleSourceFactory;
import io.github.jho951.platform.security.ip.PlatformIpRuleSource;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties.IpRuleSourceType;
import org.springframework.core.io.ResourceLoader;

import java.util.List;
import java.util.Objects;

/**
 * POLICY_CONFIG IP rule source를 처리하도록 Spring rule source factory를 확장한다.
 */
public final class PolicyConfigPlatformIpRuleSourceFactory extends SpringPlatformIpRuleSourceFactory {
    private final PolicyConfigSource policyConfigSource;

    public PolicyConfigPlatformIpRuleSourceFactory(ResourceLoader resourceLoader, PolicyConfigSource policyConfigSource) {
        super(resourceLoader);
        this.policyConfigSource = Objects.requireNonNull(policyConfigSource, "policyConfigSource");
    }

    @Override
    public PlatformIpRuleSource create(PlatformSecurityProperties.BoundaryIpGuardPolicy policy, List<String> legacyRules) {
        PlatformSecurityProperties.BoundaryIpGuardPolicy effective =
                policy == null ? new PlatformSecurityProperties.BoundaryIpGuardPolicy() : policy;
        if (effective.getSource() == IpRuleSourceType.POLICY_CONFIG) {
            String policyKey = trimToNull(effective.getPolicyKey());
            if (policyKey == null) {
                throw new IllegalStateException("IP rule source POLICY_CONFIG requires a policyKey");
            }
            return cache(new PolicyConfigPlatformIpRuleSource(policyConfigSource, policyKey), effective);
        }
        return super.create(effective, legacyRules);
    }

}
