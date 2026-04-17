package io.github.jho951.platform.security.policyconfig;

import io.github.jho951.platform.policy.api.PolicyConfigSource;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties.IpRuleSourceType;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PolicyConfigPlatformIpRuleSourceFactoryTest {
    @Test
    void policyConfigSourceReadsPolicyValue() {
        PolicyConfigSource policyConfigSource = new MapPolicyConfigSource(Map.of(
                "security.ip-guard.admin.allow-cidrs",
                "10.0.0.0/8, 203.0.113.10/32\n198.51.100.7/32"
        ));
        PlatformSecurityProperties.BoundaryIpGuardPolicy policy = new PlatformSecurityProperties.BoundaryIpGuardPolicy();
        policy.setSource(IpRuleSourceType.POLICY_CONFIG);
        policy.setPolicyKey("security.ip-guard.admin.allow-cidrs");

        PolicyConfigPlatformIpRuleSourceFactory factory =
                new PolicyConfigPlatformIpRuleSourceFactory(new DefaultResourceLoader(), policyConfigSource);

        assertEquals(
                "10.0.0.0/8\n203.0.113.10/32\n198.51.100.7/32",
                factory.create(policy, java.util.List.of()).loadRules()
        );
    }

    @Test
    void missingPolicyConfigValueFails() {
        PlatformSecurityProperties.BoundaryIpGuardPolicy policy = new PlatformSecurityProperties.BoundaryIpGuardPolicy();
        policy.setSource(IpRuleSourceType.POLICY_CONFIG);
        policy.setPolicyKey("security.ip-guard.admin.allow-cidrs");

        PolicyConfigPlatformIpRuleSourceFactory factory =
                new PolicyConfigPlatformIpRuleSourceFactory(new DefaultResourceLoader(), new MapPolicyConfigSource(Map.of()));

        assertThrows(IllegalStateException.class, () -> factory.create(policy, java.util.List.of()).loadRules());
    }

    private record MapPolicyConfigSource(Map<String, String> values) implements PolicyConfigSource {
        @Override
        public Optional<String> resolve(String key) {
            return Optional.ofNullable(values.get(key));
        }
    }
}
