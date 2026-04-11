package io.github.jho951.platform.security.autoconfigure;

import io.github.jho951.platform.security.api.SecurityPolicyService;
import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityContextResolver;
import io.github.jho951.platform.security.auth.AuthenticationCapability;
import io.github.jho951.platform.security.auth.AuthenticationCapabilityResolver;
import io.github.jho951.platform.security.auth.DefaultAuthenticationCapabilityResolver;
import io.github.jho951.platform.security.auth.DefaultHybridAuthenticationCapability;
import io.github.jho951.platform.security.auth.DefaultInternalServiceAuthenticationCapability;
import io.github.jho951.platform.security.auth.DefaultJwtAuthenticationCapability;
import io.github.jho951.platform.security.auth.DefaultSessionAuthenticationCapability;
import io.github.jho951.platform.security.auth.PlatformAuthenticationFacade;
import io.github.jho951.platform.security.core.DefaultSecurityPolicyService;
import io.github.jho951.platform.security.policy.ClientIpResolver;
import io.github.jho951.platform.security.ip.DefaultBoundaryIpPolicyProvider;
import io.github.jho951.platform.security.policy.AuthMode;
import io.github.jho951.platform.security.policy.AuthenticationModeResolver;
import io.github.jho951.platform.security.policy.BoundaryIpPolicyProvider;
import io.github.jho951.platform.security.policy.BoundaryRateLimitPolicyProvider;
import io.github.jho951.platform.security.policy.ClientTypeResolver;
import io.github.jho951.platform.security.policy.DefaultAuthenticationModeResolver;
import io.github.jho951.platform.security.policy.DefaultClientTypeResolver;
import io.github.jho951.platform.security.policy.DefaultPlatformPrincipalFactory;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.PlatformPrincipalFactory;
import io.github.jho951.platform.security.policy.RateLimitKeyResolver;
import io.github.jho951.platform.security.policy.PlatformSecurityCustomizer;
import io.github.jho951.platform.security.web.PlatformSecurityServletFilter;
import io.github.jho951.platform.security.web.PlatformSecurityWebFilter;
import io.github.jho951.platform.security.web.DefaultClientIpResolver;
import io.github.jho951.platform.security.web.PathPatternSecurityBoundaryResolver;
import io.github.jho951.platform.security.web.SecurityIngressAdapter;
import io.github.jho951.platform.security.web.SecurityIngressRequestFactory;
import io.github.jho951.platform.security.web.SecurityIdentityScrubber;
import io.github.jho951.platform.security.ratelimit.DefaultBoundaryRateLimitPolicyProvider;
import io.github.jho951.platform.security.ratelimit.DefaultRateLimitKeyResolver;
import com.auth.hybrid.DefaultHybridAuthenticationProvider;
import com.auth.hybrid.HybridAuthenticationProvider;
import com.auth.session.DefaultSessionAuthenticationProvider;
import com.auth.session.IdentitySessionPrincipalMapper;
import com.auth.session.SessionPrincipalMapper;
import com.auth.session.SessionStore;
import com.auth.session.SimpleSessionStore;
import com.auth.spi.TokenService;
import com.auth.support.jwt.JwtTokenService;
import jakarta.servlet.Filter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.web.server.WebFilter;

import java.time.Clock;

@AutoConfiguration
@ConditionalOnProperty(prefix = "platform.security", name = "enabled", havingValue = "true", matchIfMissing = true)
public class PlatformSecurityAutoConfiguration {
    @Bean
    @ConditionalOnMissingBean
    @ConfigurationProperties(prefix = "platform.security")
    public PlatformSecurityProperties platformSecurityProperties() {
        return new PlatformSecurityProperties();
    }

    @Bean
    public static BeanPostProcessor platformSecurityPropertiesCustomizerPostProcessor(
            ObjectProvider<PlatformSecurityCustomizer> customizers
    ) {
        return new BeanPostProcessor() {
            @Override
            public Object postProcessAfterInitialization(Object bean, String beanName) {
                if (bean instanceof PlatformSecurityProperties properties) {
                    customizers.orderedStream().forEach(customizer -> customizer.customize(properties));
                }
                return bean;
            }
        };
    }

    @Bean
    @ConditionalOnMissingBean(SecurityPolicyService.class)
    public SecurityPolicyService securityPolicyService(
            io.github.jho951.platform.security.policy.SecurityBoundaryResolver boundaryResolver,
            ClientTypeResolver clientTypeResolver,
            AuthenticationModeResolver authenticationModeResolver,
            BoundaryIpPolicyProvider boundaryIpPolicyProvider,
            BoundaryRateLimitPolicyProvider boundaryRateLimitPolicyProvider,
            PlatformPrincipalFactory platformPrincipalFactory
    ) {
        return new DefaultSecurityPolicyService(
                boundaryResolver,
                clientTypeResolver,
                authenticationModeResolver,
                boundaryIpPolicyProvider,
                boundaryRateLimitPolicyProvider,
                platformPrincipalFactory
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public io.github.jho951.platform.security.policy.SecurityBoundaryResolver securityBoundaryResolver(PlatformSecurityProperties properties) {
        return new PathPatternSecurityBoundaryResolver(
                properties.getBoundary().getPublicPaths(),
                properties.getBoundary().getProtectedPaths(),
                properties.getBoundary().getAdminPaths(),
                properties.getBoundary().getInternalPaths()
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public ClientTypeResolver clientTypeResolver() {
        return new DefaultClientTypeResolver();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationModeResolver authenticationModeResolver(PlatformSecurityProperties properties) {
        return new DefaultAuthenticationModeResolver(properties.getAuth());
    }

    @Bean
    @ConditionalOnMissingBean
    public PlatformPrincipalFactory platformPrincipalFactory() {
        return new DefaultPlatformPrincipalFactory();
    }

    @Bean
    @ConditionalOnMissingBean
    public BoundaryIpPolicyProvider boundaryIpPolicyProvider(PlatformSecurityProperties properties) {
        return new DefaultBoundaryIpPolicyProvider(properties.getIpGuard());
    }

    @Bean
    @ConditionalOnMissingBean
    public RateLimitKeyResolver rateLimitKeyResolver() {
        return new DefaultRateLimitKeyResolver();
    }

    @Bean
    @ConditionalOnMissingBean
    public BoundaryRateLimitPolicyProvider boundaryRateLimitPolicyProvider(
            PlatformSecurityProperties properties,
            RateLimitKeyResolver rateLimitKeyResolver
    ) {
        return new DefaultBoundaryRateLimitPolicyProvider(properties.getRateLimit(), rateLimitKeyResolver);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityIdentityScrubber securityIdentityScrubber() {
        return new SecurityIdentityScrubber();
    }

    @Bean
    @ConditionalOnMissingBean
    public ClientIpResolver clientIpResolver(PlatformSecurityProperties properties) {
        return new DefaultClientIpResolver(properties.getIpGuard());
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityIngressRequestFactory securityIngressRequestFactory(
            ClientIpResolver clientIpResolver,
            SecurityIdentityScrubber securityIdentityScrubber
    ) {
        return new SecurityIngressRequestFactory(clientIpResolver, securityIdentityScrubber);
    }

    @Bean
    @ConditionalOnMissingBean(HybridAuthenticationProvider.class)
    public HybridAuthenticationProvider authHybridAuthenticationProvider(PlatformSecurityProperties properties) {
        PlatformSecurityProperties.AuthProperties auth = properties.getAuth();
        TokenService tokenService = new JwtTokenService(
                auth.getJwtSecret(),
                auth.getAccessTokenTtl().toSeconds(),
                auth.getRefreshTokenTtl().toSeconds()
        );
        SessionStore sessionStore = new SimpleSessionStore();
        SessionPrincipalMapper mapper = new IdentitySessionPrincipalMapper();
        return new DefaultHybridAuthenticationProvider(
                tokenService,
                new DefaultSessionAuthenticationProvider(sessionStore, mapper)
        );
    }

    @Bean
    @ConditionalOnMissingBean(name = "jwtAuthenticationCapability")
    public AuthenticationCapability jwtAuthenticationCapability(HybridAuthenticationProvider authHybridAuthenticationProvider) {
        return new DefaultJwtAuthenticationCapability(authHybridAuthenticationProvider);
    }

    @Bean
    @ConditionalOnMissingBean(name = "sessionAuthenticationCapability")
    public AuthenticationCapability sessionAuthenticationCapability(HybridAuthenticationProvider authHybridAuthenticationProvider) {
        return new DefaultSessionAuthenticationCapability(authHybridAuthenticationProvider);
    }

    @Bean
    @ConditionalOnMissingBean(name = "hybridAuthenticationCapability")
    public AuthenticationCapability hybridAuthenticationCapability(HybridAuthenticationProvider authHybridAuthenticationProvider) {
        return new DefaultHybridAuthenticationCapability(authHybridAuthenticationProvider);
    }

    @Bean
    @ConditionalOnMissingBean(name = "internalAuthenticationCapability")
    public AuthenticationCapability internalAuthenticationCapability(HybridAuthenticationProvider authHybridAuthenticationProvider) {
        return new DefaultInternalServiceAuthenticationCapability(authHybridAuthenticationProvider);
    }

    @Bean
    @ConditionalOnMissingBean(AuthenticationCapabilityResolver.class)
    public AuthenticationCapabilityResolver authenticationCapabilityResolver(
            @org.springframework.beans.factory.annotation.Qualifier("jwtAuthenticationCapability") AuthenticationCapability jwtAuthenticationCapability,
            @org.springframework.beans.factory.annotation.Qualifier("sessionAuthenticationCapability") AuthenticationCapability sessionAuthenticationCapability,
            @org.springframework.beans.factory.annotation.Qualifier("hybridAuthenticationCapability") AuthenticationCapability hybridAuthenticationCapability,
            @org.springframework.beans.factory.annotation.Qualifier("internalAuthenticationCapability") AuthenticationCapability internalAuthenticationCapability
    ) {
        return new DefaultAuthenticationCapabilityResolver(
                jwtAuthenticationCapability,
                sessionAuthenticationCapability,
                hybridAuthenticationCapability,
                internalAuthenticationCapability
        );
    }

    @Bean
    @ConditionalOnMissingBean(SecurityContextResolver.class)
    public SecurityContextResolver securityContextResolver(AuthenticationCapabilityResolver authenticationCapabilityResolver) {
        return new PlatformAuthenticationFacade(authenticationCapabilityResolver);
    }

    @Bean
    @ConditionalOnMissingBean(PlatformSecurityServletFilter.class)
    @ConditionalOnClass(name = "jakarta.servlet.Filter")
    public Filter securityServletFilter(
            SecurityIngressAdapter securityIngressAdapter,
            SecurityContextResolver securityContextResolver,
            SecurityIngressRequestFactory securityIngressRequestFactory
    ) {
        return new PlatformSecurityServletFilter(securityIngressAdapter, securityContextResolver, Clock.systemUTC(), securityIngressRequestFactory);
    }

    @Bean
    @ConditionalOnClass(WebFilter.class)
    @ConditionalOnMissingBean(PlatformSecurityWebFilter.class)
    public WebFilter securityWebFilter(
            SecurityIngressAdapter securityIngressAdapter,
            SecurityContextResolver securityContextResolver,
            SecurityIngressRequestFactory securityIngressRequestFactory
    ) {
        return new PlatformSecurityWebFilter(securityIngressAdapter, securityContextResolver, Clock.systemUTC(), securityIngressRequestFactory);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityIngressAdapter securityIngressAdapter(
            SecurityPolicyService securityPolicyService,
            io.github.jho951.platform.security.policy.SecurityBoundaryResolver boundaryResolver
    ) {
        return new SecurityIngressAdapter(securityPolicyService, boundaryResolver);
    }
}
