package io.github.jho951.platform.security.policyconfig;

import io.github.jho951.platform.policy.api.PolicyConfigSource;
import io.github.jho951.platform.security.autoconfigure.PlatformSecurityAutoConfiguration;
import io.github.jho951.platform.security.ip.PlatformIpRuleSourceFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;

/**
 * platform-policy-api policy config source를 IP guard rule source로 연결하는 자동 구성이다.
 */
@AutoConfiguration
@AutoConfigureBefore(PlatformSecurityAutoConfiguration.class)
public class PlatformSecurityPolicyConfigBridgeAutoConfiguration {
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "io.github.jho951.platform.governance.api.PolicyConfigSource")
    static class GovernancePolicyConfigSourceAdapterConfiguration {
        @Bean
        @ConditionalOnBean(io.github.jho951.platform.governance.api.PolicyConfigSource.class)
        @ConditionalOnMissingBean(PolicyConfigSource.class)
        PolicyConfigSource governancePolicyConfigSourceAdapter(
                io.github.jho951.platform.governance.api.PolicyConfigSource policyConfigSource
        ) {
            return policyConfigSource::resolve;
        }
    }

    @Bean
    @ConditionalOnBean(PolicyConfigSource.class)
    @ConditionalOnMissingBean(PlatformIpRuleSourceFactory.class)
    public PlatformIpRuleSourceFactory platformPolicyConfigIpRuleSourceFactory(
            ResourceLoader resourceLoader,
            PolicyConfigSource policyConfigSource
    ) {
        return new PolicyConfigPlatformIpRuleSourceFactory(resourceLoader, policyConfigSource);
    }
}
