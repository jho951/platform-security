package io.github.jho951.platform.security.client;

import jakarta.servlet.Filter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;

/**
 * outbound security propagation client support를 자동 구성한다.
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "platform.security.client", name = "enabled", havingValue = "true", matchIfMissing = true)
public class PlatformSecurityClientAutoConfiguration {
    @Bean
    @ConditionalOnClass(Filter.class)
    @ConditionalOnMissingBean(SecurityOutboundServletContextFilter.class)
    public Filter securityOutboundServletContextFilter() {
        return new SecurityOutboundServletContextFilter();
    }

    @Bean
    @ConditionalOnClass(ClientHttpRequestInterceptor.class)
    @ConditionalOnMissingBean(SecurityClientHttpRequestInterceptor.class)
    public ClientHttpRequestInterceptor securityClientHttpRequestInterceptor() {
        return new SecurityClientHttpRequestInterceptor();
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityFeignHeaderApplier securityFeignHeaderApplier() {
        return new SecurityFeignHeaderApplier();
    }

    @Bean
    @ConditionalOnClass(name = "feign.RequestInterceptor")
    @ConditionalOnMissingBean(type = "feign.RequestInterceptor")
    public Object securityFeignRequestInterceptor() {
        return SecurityFeignRequestInterceptorFactory.create();
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.web.reactive.function.client.ExchangeFilterFunction")
    static class WebClientPropagationConfiguration {
        @Bean
        @ConditionalOnMissingBean(SecurityWebClientExchangeFilterFunction.class)
        ExchangeFilterFunction securityWebClientExchangeFilterFunction() {
            return new SecurityWebClientExchangeFilterFunction();
        }
    }
}
