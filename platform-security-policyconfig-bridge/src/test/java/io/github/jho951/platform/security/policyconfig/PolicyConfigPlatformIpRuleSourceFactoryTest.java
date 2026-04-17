package io.github.jho951.platform.security.policyconfig;

import io.github.jho951.platform.policy.api.PolicyConfigSource;
import io.github.jho951.platform.security.ip.PlatformIpRuleSourceFactory;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties.IpRuleSourceType;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.io.DefaultResourceLoader;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
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

    @Test
    void autoConfigurationAdaptsGovernancePolicyConfigSource() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(PlatformSecurityPolicyConfigBridgeAutoConfiguration.class))
                .withBean(
                        io.github.jho951.platform.governance.api.PolicyConfigSource.class,
                        () -> new GovernanceMapPolicyConfigSource(Map.of(
                                "security.ip-guard.admin.allow-cidrs",
                                "10.0.0.0/8, 203.0.113.10/32"
                        ))
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(PolicyConfigSource.class);
                    assertThat(context).hasSingleBean(PlatformIpRuleSourceFactory.class);

                    PlatformSecurityProperties.BoundaryIpGuardPolicy policy =
                            new PlatformSecurityProperties.BoundaryIpGuardPolicy();
                    policy.setSource(IpRuleSourceType.POLICY_CONFIG);
                    policy.setPolicyKey("security.ip-guard.admin.allow-cidrs");

                    PlatformIpRuleSourceFactory factory = context.getBean(PlatformIpRuleSourceFactory.class);
                    assertEquals("10.0.0.0/8\n203.0.113.10/32", factory.create(policy, java.util.List.of()).loadRules());
                });
    }

    private record MapPolicyConfigSource(Map<String, String> values) implements PolicyConfigSource {
        @Override
        public Optional<String> resolve(String key) {
            return Optional.ofNullable(values.get(key));
        }
    }

    private record GovernanceMapPolicyConfigSource(Map<String, String> values)
            implements io.github.jho951.platform.governance.api.PolicyConfigSource {
        @Override
        public Optional<String> resolve(String key) {
            return Optional.ofNullable(values.get(key));
        }

        @Override
        public Map<String, String> snapshot() {
            return values;
        }
    }
}
