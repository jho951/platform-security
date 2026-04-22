package io.github.jho951.platform.security.autoconfigure;

import io.github.jho951.platform.security.api.PlatformSecurityHybridWebAdapterMarker;
import io.github.jho951.platform.security.api.SecurityAuditPublisher;
import io.github.jho951.platform.security.api.SecurityContextResolver;
import io.github.jho951.platform.security.hybrid.PlatformSecurityGatewayIntegration;
import io.github.jho951.platform.security.hybrid.PlatformSecurityReactiveGatewayIntegration;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.web.PlatformSecurityServletFilter;
import io.github.jho951.platform.security.web.PlatformSecurityWebFilter;
import io.github.jho951.platform.security.web.ReactiveSecurityFailureResponseWriter;
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
import org.springframework.web.server.WebFilter;

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
    @ConditionalOnMissingBean(PlatformSecurityWebFilter.class)
    @ConditionalOnClass(WebFilter.class)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
    public PlatformSecurityWebFilter securityWebFilter(
            SecurityIngressAdapter securityIngressAdapter,
            SecurityContextResolver securityContextResolver,
            SecurityIngressRequestFactory securityIngressRequestFactory,
            SecurityDownstreamIdentityPropagator downstreamIdentityPropagator,
            SecurityAuditPublisher securityAuditPublisher,
            ReactiveSecurityFailureResponseWriter reactiveSecurityFailureResponseWriter
    ) {
        return new PlatformSecurityWebFilter(
                securityIngressAdapter,
                securityContextResolver,
                Clock.systemUTC(),
                securityIngressRequestFactory,
                downstreamIdentityPropagator,
                securityAuditPublisher,
                reactiveSecurityFailureResponseWriter
        );
    }

    @Bean
    @ConditionalOnMissingBean(ReactiveGatewayHeaderAuthenticationWebFilter.class)
    @ConditionalOnClass(WebFilter.class)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
    public ReactiveGatewayHeaderAuthenticationWebFilter reactiveGatewayHeaderAuthenticationWebFilter(
            PlatformSecurityProperties properties
    ) {
        return new ReactiveGatewayHeaderAuthenticationWebFilter(properties.getAuth().getGatewayHeader());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(PlatformSecurityServletFilter.class)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
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

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(PlatformSecurityWebFilter.class)
    @ConditionalOnClass(WebFilter.class)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
    public PlatformSecurityReactiveGatewayIntegration platformSecurityReactiveGatewayIntegration(
            SecurityIngressAdapter securityIngressAdapter,
            PlatformSecurityWebFilter platformSecurityWebFilter,
            ReactiveSecurityFailureResponseWriter reactiveSecurityFailureResponseWriter,
            SecurityAuditPublisher securityAuditPublisher,
            @org.springframework.beans.factory.annotation.Qualifier("reactiveGatewayHeaderAuthenticationWebFilter")
            ObjectProvider<WebFilter> gatewayHeaderAuthenticationWebFilterProvider
    ) {
        return new PlatformSecurityReactiveGatewayIntegration(
                securityIngressAdapter,
                platformSecurityWebFilter,
                gatewayHeaderAuthenticationWebFilterProvider.getIfAvailable(),
                reactiveSecurityFailureResponseWriter,
                securityAuditPublisher
        );
    }
}
