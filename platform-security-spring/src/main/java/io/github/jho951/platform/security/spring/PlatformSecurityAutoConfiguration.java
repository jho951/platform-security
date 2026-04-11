package io.github.jho951.platform.security.spring;

import com.ipguard.core.engine.IpGuardEngine;
import com.ipguard.spi.RuleSource;
import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.SecurityPolicyService;
import io.github.jho951.platform.security.core.DefaultSecurityPolicyService;
import io.github.jho951.platform.security.core.policy.FixedWindowRateLimitPolicy;
import io.github.jho951.platform.security.core.policy.IpAllowListPolicy;
import io.github.jho951.platform.security.core.policy.RequireAuthenticatedPolicy;
import io.github.jho951.platform.security.web.SecurityBoundaryResolver;
import io.github.jho951.platform.security.web.SecurityContextResolver;
import io.github.jho951.platform.security.web.SecurityIdentityScrubber;
import io.github.jho951.platform.security.web.SecurityIngressAdapter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import jakarta.servlet.Filter;

import java.time.Clock;
import java.util.List;
import java.util.stream.Collectors;

@AutoConfiguration
@ConditionalOnProperty(prefix = "platform.security", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(PlatformSecurityProperties.class)
public class PlatformSecurityAutoConfiguration {
    @Bean
    @Order(1)
    @ConditionalOnMissingBean(name = "authPolicy")
    public SecurityPolicy authPolicy(PlatformSecurityProperties properties) {
        if (!properties.getAuthentication().isRequired()) {
            return new SecurityPolicy() {
                @Override
                public String name() {
                    return "auth";
                }

                @Override
                public io.github.jho951.platform.security.api.SecurityVerdict evaluate(
                        io.github.jho951.platform.security.api.SecurityRequest request,
                        io.github.jho951.platform.security.api.SecurityContext context
                ) {
                    return io.github.jho951.platform.security.api.SecurityVerdict.allow(name(), "disabled");
                }
            };
        }
        return new RequireAuthenticatedPolicy();
    }

    @Bean
    @Order(2)
    @ConditionalOnMissingBean(name = "ipGuardPolicy")
    @ConditionalOnProperty(prefix = "platform.security.ip-guard", name = "enabled", havingValue = "true")
    public SecurityPolicy ipGuardPolicy(IpGuardEngine ipGuardEngine) {
        return new IpAllowListPolicy(ipGuardEngine);
    }

    @Bean
    @Order(3)
    @ConditionalOnMissingBean(name = "rateLimitPolicy")
    @ConditionalOnProperty(prefix = "platform.security.rate-limit", name = "enabled", havingValue = "true")
    public SecurityPolicy rateLimitPolicy(PlatformSecurityProperties properties) {
        PlatformSecurityProperties.RateLimit rateLimit = properties.getRateLimit();
        return new FixedWindowRateLimitPolicy(rateLimit.getLimit(), rateLimit.getWindow());
    }

    @Bean
    @ConditionalOnMissingBean(SecurityPolicyService.class)
    public SecurityPolicyService securityPolicyService(List<SecurityPolicy> policies) {
        return new DefaultSecurityPolicyService(policies);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityBoundaryResolver securityBoundaryResolver() {
        return new SecurityBoundaryResolver();
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityIdentityScrubber securityIdentityScrubber() {
        return new SecurityIdentityScrubber();
    }

    @Bean
    @ConditionalOnMissingBean(SecurityContextResolver.class)
    public SecurityContextResolver securityContextResolver(PlatformSecurityProperties properties) {
        PlatformSecurityProperties.Auth auth = properties.getAuth();
        return new io.github.jho951.platform.security.auth.AuthServerSecurityContextResolver(
                auth.getJwtSecret(),
                auth.getAccessTokenTtl().toSeconds(),
                auth.getRefreshTokenTtl().toSeconds()
        );
    }

    @Bean
    @ConditionalOnMissingBean(Filter.class)
    public Filter securityServletFilter(
            SecurityIngressAdapter securityIngressAdapter,
            SecurityContextResolver securityContextResolver
    ) {
        return new io.github.jho951.platform.security.auth.AuthServerSecurityServletFilter(securityIngressAdapter, securityContextResolver);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityIngressAdapter securityIngressAdapter(
            SecurityPolicyService securityPolicyService,
            SecurityBoundaryResolver boundaryResolver
    ) {
        return new SecurityIngressAdapter(securityPolicyService, boundaryResolver);
    }

    @Bean
    @ConditionalOnMissingBean
    public Clock platformSecurityClock() {
        return Clock.systemUTC();
    }

    @Bean
    @ConditionalOnMissingBean
    public RuleSource platformSecurityRuleSource(PlatformSecurityProperties properties) {
        return () -> properties.getIpGuard().getAllowedIps().stream().collect(Collectors.joining("\n"));
    }

    @Bean
    @ConditionalOnMissingBean
    public IpGuardEngine ipGuardEngine(RuleSource ruleSource) {
        return new IpGuardEngine(ruleSource, true);
    }

}
