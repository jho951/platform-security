package io.github.jho951.platform.security.policyconfig;

import io.github.jho951.platform.governance.api.PolicyConfigSource;
import io.github.jho951.platform.security.autoconfigure.PlatformSecurityAutoConfiguration;
import io.github.jho951.platform.security.ip.PlatformIpRuleSourceFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ResourceLoader;

/**
 * governance policy config source를 IP guard rule source로 연결하는 자동 구성이다.
 */
@AutoConfiguration
@AutoConfigureAfter(name = "io.github.jho951.platform.governance.spring.PlatformGovernanceAutoConfiguration")
@AutoConfigureBefore(PlatformSecurityAutoConfiguration.class)
@ConditionalOnClass(PolicyConfigSource.class)
public class PlatformSecurityPolicyConfigBridgeAutoConfiguration {
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
