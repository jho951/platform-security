package io.github.jho951.platform.security.autoconfigure;

import io.github.jho951.platform.security.api.SecurityPolicyService;
import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityContextResolver;
import io.github.jho951.platform.security.auth.AuthenticationCapability;
import io.github.jho951.platform.security.auth.AuthenticationCapabilityResolver;
import io.github.jho951.platform.security.auth.DefaultApiKeyAuthenticationCapability;
import io.github.jho951.platform.security.auth.DefaultAuthenticationCapabilityResolver;
import io.github.jho951.platform.security.auth.DefaultHmacAuthenticationCapability;
import io.github.jho951.platform.security.auth.DefaultHybridAuthenticationCapability;
import io.github.jho951.platform.security.auth.DefaultInternalServiceAuthenticationCapability;
import io.github.jho951.platform.security.auth.DefaultJwtAuthenticationCapability;
import io.github.jho951.platform.security.auth.DefaultOAuth2PrincipalBridge;
import io.github.jho951.platform.security.auth.DefaultOidcPrincipalMapper;
import io.github.jho951.platform.security.auth.DefaultOidcAuthenticationCapability;
import io.github.jho951.platform.security.auth.DefaultServiceAccountAuthenticationCapability;
import io.github.jho951.platform.security.auth.DefaultSessionIssuanceCapability;
import io.github.jho951.platform.security.auth.DefaultSessionAuthenticationCapability;
import io.github.jho951.platform.security.auth.DefaultTokenIssuanceCapability;
import io.github.jho951.platform.security.auth.PlatformSecurityContextResolvers;
import io.github.jho951.platform.security.auth.InternalTokenClaimsValidator;
import io.github.jho951.platform.security.auth.OAuth2PrincipalBridge;
import io.github.jho951.platform.security.auth.SessionIssuanceCapability;
import io.github.jho951.platform.security.auth.TokenIssuanceCapability;
import io.github.jho951.platform.security.core.DefaultSecurityPolicyService;
import io.github.jho951.platform.security.policy.ClientIpResolver;
import io.github.jho951.platform.security.ip.DefaultBoundaryIpPolicyProvider;
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
import io.github.jho951.platform.security.web.SecurityAuditPublisher;
import io.github.jho951.platform.security.web.SecurityDownstreamIdentityPropagator;
import io.github.jho951.platform.security.ratelimit.DefaultBoundaryRateLimitPolicyProvider;
import io.github.jho951.platform.security.ratelimit.DefaultRateLimitKeyResolver;
import com.auth.apikey.ApiKeyAuthenticationProvider;
import com.auth.apikey.ApiKeyPrincipalResolver;
import com.auth.hmac.HmacAuthenticationProvider;
import com.auth.hmac.HmacPrincipalResolver;
import com.auth.hmac.HmacSecretResolver;
import com.auth.hmac.HmacSignatureVerifier;
import com.auth.hybrid.DefaultHybridAuthenticationProvider;
import com.auth.hybrid.HybridAuthenticationProvider;
import com.auth.oidc.OidcAuthenticationProvider;
import com.auth.oidc.OidcPrincipalMapper;
import com.auth.oidc.OidcTokenVerifier;
import com.auth.serviceaccount.ServiceAccountAuthenticationProvider;
import com.auth.serviceaccount.ServiceAccountVerifier;
import com.auth.session.DefaultSessionAuthenticationProvider;
import com.auth.session.IdentitySessionPrincipalMapper;
import com.auth.session.SessionPrincipalMapper;
import com.auth.session.SessionStore;
import com.auth.session.SimpleSessionStore;
import com.auth.spi.OAuth2PrincipalResolver;
import com.auth.spi.TokenService;
import com.auth.support.jwt.JwtTokenService;
import jakarta.servlet.Filter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.web.server.WebFilter;

import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Set;

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
    public HybridAuthenticationProvider authHybridAuthenticationProvider(
            TokenService tokenService,
            SessionStore sessionStore,
            SessionPrincipalMapper mapper
    ) {
        return new DefaultHybridAuthenticationProvider(
                tokenService,
                new DefaultSessionAuthenticationProvider(sessionStore, mapper)
        );
    }

    @Bean
    @ConditionalOnMissingBean(TokenService.class)
    public TokenService platformSecurityTokenService(PlatformSecurityProperties properties) {
        PlatformSecurityProperties.AuthProperties auth = properties.getAuth();
        return new JwtTokenService(
                auth.getJwtSecret(),
                auth.getAccessTokenTtl().toSeconds(),
                auth.getRefreshTokenTtl().toSeconds()
        );
    }

    @Bean
    @ConditionalOnMissingBean(SessionStore.class)
    public SessionStore platformSecuritySessionStore() {
        return new SimpleSessionStore();
    }

    @Bean
    @ConditionalOnMissingBean(SessionPrincipalMapper.class)
    public SessionPrincipalMapper platformSecuritySessionPrincipalMapper() {
        return new IdentitySessionPrincipalMapper();
    }

    @Bean
    @ConditionalOnMissingBean(InternalTokenClaimsValidator.class)
    public InternalTokenClaimsValidator internalTokenClaimsValidator() {
        return InternalTokenClaimsValidator.allowAll();
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
    public AuthenticationCapability internalAuthenticationCapability(
            HybridAuthenticationProvider authHybridAuthenticationProvider,
            InternalTokenClaimsValidator internalTokenClaimsValidator
    ) {
        return new DefaultInternalServiceAuthenticationCapability(authHybridAuthenticationProvider, internalTokenClaimsValidator);
    }

    @Bean
    @ConditionalOnMissingBean(ApiKeyAuthenticationProvider.class)
    @ConditionalOnBean(ApiKeyPrincipalResolver.class)
    public ApiKeyAuthenticationProvider apiKeyAuthenticationProvider(ApiKeyPrincipalResolver resolver) {
        return new ApiKeyAuthenticationProvider(resolver);
    }

    @Bean
    @ConditionalOnMissingBean(name = "apiKeyAuthenticationCapability")
    @ConditionalOnBean(ApiKeyAuthenticationProvider.class)
    public AuthenticationCapability apiKeyAuthenticationCapability(ApiKeyAuthenticationProvider apiKeyAuthenticationProvider) {
        return new DefaultApiKeyAuthenticationCapability(apiKeyAuthenticationProvider);
    }

    @Bean
    @ConditionalOnMissingBean(HmacAuthenticationProvider.class)
    @ConditionalOnBean({HmacSecretResolver.class, HmacSignatureVerifier.class, HmacPrincipalResolver.class})
    public HmacAuthenticationProvider hmacAuthenticationProvider(
            HmacSecretResolver secretResolver,
            HmacSignatureVerifier signatureVerifier,
            HmacPrincipalResolver principalResolver
    ) {
        return new HmacAuthenticationProvider(secretResolver, signatureVerifier, principalResolver);
    }

    @Bean
    @ConditionalOnMissingBean(name = "hmacAuthenticationCapability")
    @ConditionalOnBean(HmacAuthenticationProvider.class)
    public AuthenticationCapability hmacAuthenticationCapability(HmacAuthenticationProvider hmacAuthenticationProvider) {
        return new DefaultHmacAuthenticationCapability(hmacAuthenticationProvider);
    }

    @Bean
    @ConditionalOnMissingBean(OidcPrincipalMapper.class)
    public OidcPrincipalMapper oidcPrincipalMapper(PlatformSecurityProperties properties) {
        return new DefaultOidcPrincipalMapper(properties.getAuth().getOidc());
    }

    @Bean
    @ConditionalOnMissingBean(OidcAuthenticationProvider.class)
    @ConditionalOnBean({OidcTokenVerifier.class, OidcPrincipalMapper.class})
    public OidcAuthenticationProvider oidcAuthenticationProvider(
            OidcTokenVerifier tokenVerifier,
            OidcPrincipalMapper principalMapper
    ) {
        return new OidcAuthenticationProvider(tokenVerifier, principalMapper);
    }

    @Bean
    @ConditionalOnMissingBean(name = "oidcAuthenticationCapability")
    @ConditionalOnBean(OidcAuthenticationProvider.class)
    public AuthenticationCapability oidcAuthenticationCapability(OidcAuthenticationProvider oidcAuthenticationProvider) {
        return new DefaultOidcAuthenticationCapability(oidcAuthenticationProvider);
    }

    @Bean
    @ConditionalOnMissingBean(ServiceAccountAuthenticationProvider.class)
    @ConditionalOnBean(ServiceAccountVerifier.class)
    public ServiceAccountAuthenticationProvider serviceAccountAuthenticationProvider(ServiceAccountVerifier verifier) {
        return new ServiceAccountAuthenticationProvider(verifier);
    }

    @Bean
    @ConditionalOnMissingBean(name = "serviceAccountAuthenticationCapability")
    @ConditionalOnBean(ServiceAccountAuthenticationProvider.class)
    public AuthenticationCapability serviceAccountAuthenticationCapability(
            ServiceAccountAuthenticationProvider serviceAccountAuthenticationProvider
    ) {
        return new DefaultServiceAccountAuthenticationCapability(serviceAccountAuthenticationProvider);
    }

    @Bean
    @ConditionalOnMissingBean(OAuth2PrincipalBridge.class)
    @ConditionalOnBean(OAuth2PrincipalResolver.class)
    public OAuth2PrincipalBridge oauth2PrincipalBridge(OAuth2PrincipalResolver resolver) {
        return new DefaultOAuth2PrincipalBridge(resolver);
    }

    @Bean
    @ConditionalOnMissingBean(TokenIssuanceCapability.class)
    public TokenIssuanceCapability tokenIssuanceCapability(TokenService tokenService) {
        return new DefaultTokenIssuanceCapability(tokenService);
    }

    @Bean
    @ConditionalOnMissingBean(SessionIssuanceCapability.class)
    public SessionIssuanceCapability sessionIssuanceCapability(SessionStore sessionStore) {
        return new DefaultSessionIssuanceCapability(sessionStore);
    }

    @Bean
    @ConditionalOnMissingBean(AuthenticationCapabilityResolver.class)
    public AuthenticationCapabilityResolver authenticationCapabilityResolver(
            @org.springframework.beans.factory.annotation.Qualifier("jwtAuthenticationCapability") AuthenticationCapability jwtAuthenticationCapability,
            @org.springframework.beans.factory.annotation.Qualifier("sessionAuthenticationCapability") AuthenticationCapability sessionAuthenticationCapability,
            @org.springframework.beans.factory.annotation.Qualifier("hybridAuthenticationCapability") AuthenticationCapability hybridAuthenticationCapability,
            @org.springframework.beans.factory.annotation.Qualifier("internalAuthenticationCapability") AuthenticationCapability internalAuthenticationCapability,
            @org.springframework.beans.factory.annotation.Qualifier("apiKeyAuthenticationCapability") ObjectProvider<AuthenticationCapability> apiKeyAuthenticationCapability,
            @org.springframework.beans.factory.annotation.Qualifier("hmacAuthenticationCapability") ObjectProvider<AuthenticationCapability> hmacAuthenticationCapability,
            @org.springframework.beans.factory.annotation.Qualifier("oidcAuthenticationCapability") ObjectProvider<AuthenticationCapability> oidcAuthenticationCapability,
            @org.springframework.beans.factory.annotation.Qualifier("serviceAccountAuthenticationCapability") ObjectProvider<AuthenticationCapability> serviceAccountAuthenticationCapability
    ) {
        return new DefaultAuthenticationCapabilityResolver(
                jwtAuthenticationCapability,
                sessionAuthenticationCapability,
                hybridAuthenticationCapability,
                internalAuthenticationCapability,
                apiKeyAuthenticationCapability.getIfAvailable(),
                hmacAuthenticationCapability.getIfAvailable(),
                oidcAuthenticationCapability.getIfAvailable(),
                serviceAccountAuthenticationCapability.getIfAvailable()
        );
    }

    @Bean
    @ConditionalOnMissingBean(SecurityContextResolver.class)
    @ConditionalOnProperty(prefix = "platform.security.auth", name = "enabled", havingValue = "true", matchIfMissing = true)
    @ConditionalOnProperty(prefix = "platform.security.auth.dev-fallback", name = "enabled", havingValue = "true")
    public SecurityContextResolver devFallbackSecurityContextResolver() {
        return PlatformSecurityContextResolvers.devFallback();
    }

    @Bean
    @ConditionalOnMissingBean(SecurityContextResolver.class)
    @ConditionalOnProperty(prefix = "platform.security.auth", name = "enabled", havingValue = "false")
    public SecurityContextResolver anonymousSecurityContextResolver() {
        return request -> new SecurityContext(false, null, Set.of(), new LinkedHashMap<>(request.attributes()));
    }

    @Bean
    @ConditionalOnProperty(prefix = "platform.security.auth", name = "enabled", havingValue = "true", matchIfMissing = true)
    public org.springframework.beans.factory.SmartInitializingSingleton securityContextResolverGuard(
            ObjectProvider<SecurityContextResolver> resolverProvider
    ) {
        return () -> {
            if (resolverProvider.getIfAvailable() == null) {
                throw new IllegalStateException(
                        "No SecurityContextResolver configured. " +
                                "Provide a production SecurityContextResolver bean, " +
                                "or explicitly enable platform.security.auth.dev-fallback.enabled=true for local/test."
                );
            }
        };
    }

    @Bean
    @ConditionalOnMissingBean(PlatformSecurityServletFilter.class)
    @ConditionalOnBean(SecurityContextResolver.class)
    @ConditionalOnClass(name = "jakarta.servlet.Filter")
    public Filter securityServletFilter(
            SecurityIngressAdapter securityIngressAdapter,
            SecurityContextResolver securityContextResolver,
            SecurityIngressRequestFactory securityIngressRequestFactory,
            SecurityDownstreamIdentityPropagator downstreamIdentityPropagator,
            SecurityAuditPublisher securityAuditPublisher
    ) {
        return new PlatformSecurityServletFilter(
                securityIngressAdapter,
                securityContextResolver,
                Clock.systemUTC(),
                securityIngressRequestFactory,
                downstreamIdentityPropagator,
                securityAuditPublisher
        );
    }

    @Bean
    @ConditionalOnClass(WebFilter.class)
    @ConditionalOnMissingBean(PlatformSecurityWebFilter.class)
    @ConditionalOnBean(SecurityContextResolver.class)
    public WebFilter securityWebFilter(
            SecurityIngressAdapter securityIngressAdapter,
            SecurityContextResolver securityContextResolver,
            SecurityIngressRequestFactory securityIngressRequestFactory,
            SecurityDownstreamIdentityPropagator downstreamIdentityPropagator,
            SecurityAuditPublisher securityAuditPublisher
    ) {
        return new PlatformSecurityWebFilter(
                securityIngressAdapter,
                securityContextResolver,
                Clock.systemUTC(),
                securityIngressRequestFactory,
                downstreamIdentityPropagator,
                securityAuditPublisher
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityDownstreamIdentityPropagator securityDownstreamIdentityPropagator() {
        return new SecurityDownstreamIdentityPropagator();
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityAuditPublisher securityAuditPublisher() {
        return SecurityAuditPublisher.noop();
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
