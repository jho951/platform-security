package io.github.jho951.platform.security.ip;

import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties.IpRuleSourceType;

import java.util.List;

/**
 * inline IP rule만 처리하는 기본 rule source factory다.
 *
 * <p>FILE, POLICY_CONFIG 같은 외부 source는 autoconfigure 또는 bridge 모듈이 확장한다.</p>
 */
public class DefaultPlatformIpRuleSourceFactory implements PlatformIpRuleSourceFactory {
    @Override
    public PlatformIpRuleSource create(PlatformSecurityProperties.BoundaryIpGuardPolicy policy, List<String> legacyRules) {
        PlatformSecurityProperties.BoundaryIpGuardPolicy effective =
                policy == null ? new PlatformSecurityProperties.BoundaryIpGuardPolicy() : policy;
        if (effective.getSource() != IpRuleSourceType.INLINE) {
            throw new IllegalStateException("Unsupported IP rule source without bridge/autoconfigure support: " + effective.getSource());
        }
        List<String> rules = effective.getRules().isEmpty() ? legacyRules : effective.getRules();
        return new InlinePlatformIpRuleSource(rules);
    }
}
