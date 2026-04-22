package io.github.jho951.platform.security.autoconfigure;

import io.github.jho951.platform.security.api.PlatformSecurityHybridWebAdapterMarker;
import io.github.jho951.platform.security.api.SecurityAuditPublisher;
import io.github.jho951.platform.security.api.SecurityContextResolver;
import io.github.jho951.platform.security.hybrid.PlatformSecurityGatewayIntegration;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.web.PlatformSecurityServletFilter;
import io.github.jho951.platform.security.web.SecurityDownstreamIdentityPropagator;
import io.github.jho951.platform.security.web.SecurityFailureResponseWriter;
import io.github.jho951.platform.security.web.SecurityIngressAdapter;
import io.github.jho951.platform.security.web.SecurityIngressRequestFactory;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;

import java.time.Clock;

/**
 * platform-security의 기본 web filter/chain auto-registration을 끄고,
 * 안전한 core/web 조립 bean만 남기는 hybrid adapter 모드다.
 */
@AutoConfiguration
@AutoConfigureBefore(name = "io.github.jho951.platform.security.autoconfigure.PlatformSecurityAutoConfiguration")
public class PlatformSecurityHybridWebAdapterAutoConfiguration {

    @Bean
    public PlatformSecurityHybridWebAdapterMarker platformSecurityHybridWebAdapterMarker() {
        return new PlatformSecurityHybridWebAdapterMarker() {
        };
    }

    @Bean
    @ConditionalOnMissingBean(PlatformSecurityServletFilter.class)
    @ConditionalOnClass(name = "jakarta.servlet.Filter")
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    public PlatformSecurityServletFilter securityServletFilter(
            SecurityIngressAdapter securityIngressAdapter,
            SecurityContextResolver securityContextResolver,
            SecurityIngressRequestFactory securityIngressRequestFactory,
            SecurityDownstreamIdentityPropagator downstreamIdentityPropagator,
            SecurityAuditPublisher securityAuditPublisher,
            SecurityFailureResponseWriter failureResponseWriter
    ) {
        return new PlatformSecurityServletFilter(
                securityIngressAdapter,
                securityContextResolver,
                Clock.systemUTC(),
                securityIngressRequestFactory,
                downstreamIdentityPropagator,
                securityAuditPublisher,
                failureResponseWriter
        );
    }

    @Bean
    @ConditionalOnMissingBean(GatewayHeaderAuthenticationFilter.class)
    @ConditionalOnClass(name = "jakarta.servlet.Filter")
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    public GatewayHeaderAuthenticationFilter gatewayHeaderAuthenticationFilter(PlatformSecurityProperties properties) {
        return new GatewayHeaderAuthenticationFilter(properties.getAuth().getGatewayHeader());
    }

    @Bean
    @ConditionalOnMissingBean
    public PlatformSecurityGatewayIntegration platformSecurityGatewayIntegration(
            SecurityIngressAdapter securityIngressAdapter,
            PlatformSecurityServletFilter platformSecurityServletFilter,
            SecurityFailureResponseWriter securityFailureResponseWriter,
            SecurityAuditPublisher securityAuditPublisher,
            @org.springframework.beans.factory.annotation.Qualifier("gatewayHeaderAuthenticationFilter")
            ObjectProvider<jakarta.servlet.Filter> gatewayHeaderAuthenticationFilterProvider
    ) {
        return new PlatformSecurityGatewayIntegration(
                securityIngressAdapter,
                platformSecurityServletFilter,
                gatewayHeaderAuthenticationFilterProvider.getIfAvailable(),
                securityFailureResponseWriter,
                securityAuditPublisher
        );
    }
}
