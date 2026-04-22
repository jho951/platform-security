package io.github.jho951.platform.security.autoconfigure;

import io.github.jho951.platform.security.api.SecurityPolicyService;
import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityContextResolver;
import io.github.jho951.platform.security.api.SecurityAuditPublisher;
import io.github.jho951.platform.security.api.PlatformSecurityHybridWebAdapterMarker;
import io.github.jho951.platform.policy.api.OperationalProfileResolver;
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
import io.github.jho951.platform.security.auth.DefaultPlatformSessionSupportFactory;
import io.github.jho951.platform.security.auth.DefaultServiceAccountAuthenticationCapability;
import io.github.jho951.platform.security.auth.DefaultSessionAuthenticationCapability;
import io.github.jho951.platform.security.auth.InternalTokenClaimsValidator;
import io.github.jho951.platform.security.auth.OAuth2PrincipalBridge;
import io.github.jho951.platform.security.auth.PlatformSessionIssuerPort;
import io.github.jho951.platform.security.auth.PlatformSessionSupport;
import io.github.jho951.platform.security.auth.PlatformSessionSupportFactory;
import io.github.jho951.platform.security.auth.PlatformTokenIssuerPort;
import io.github.jho951.platform.security.core.DefaultSecurityPolicyService;
import io.github.jho951.platform.security.policy.ClientIpResolver;
import io.github.jho951.platform.security.ip.DefaultBoundaryIpPolicyProvider;
import io.github.jho951.platform.security.ip.PlatformIpRuleSourceFactory;
import io.github.jho951.platform.security.policy.AuthenticationModeResolver;
import io.github.jho951.platform.security.policy.BoundaryIpPolicyProvider;
import io.github.jho951.platform.security.policy.BoundaryRateLimitPolicyProvider;
import io.github.jho951.platform.security.policy.ClientTypeResolver;
import io.github.jho951.platform.security.policy.DefaultAuthenticationModeResolver;
import io.github.jho951.platform.security.policy.DefaultClientTypeResolver;
import io.github.jho951.platform.security.policy.DefaultPlatformPrincipalFactory;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.PlatformPrincipalFactory;
import io.github.jho951.platform.security.policy.OperationalSecurityPolicyEnforcer;
import io.github.jho951.platform.security.policy.PlatformSecurityPresetApplier;
import io.github.jho951.platform.security.policy.RateLimitKeyResolver;
import io.github.jho951.platform.security.policy.PlatformSecurityCustomizer;
import io.github.jho951.platform.security.web.PlatformSecurityServletFilter;
import io.github.jho951.platform.security.web.PlatformSecurityWebFilter;
import io.github.jho951.platform.security.web.DefaultClientIpResolver;
import io.github.jho951.platform.security.web.PathPatternSecurityBoundaryResolver;
import io.github.jho951.platform.security.web.SecurityIngressAdapter;
import io.github.jho951.platform.security.web.SecurityIngressRequestFactory;
import io.github.jho951.platform.security.web.SecurityIdentityScrubber;
import io.github.jho951.platform.security.web.SecurityDownstreamIdentityPropagator;
import io.github.jho951.platform.security.web.SecurityFailureResponse;
import io.github.jho951.platform.security.web.SecurityFailureResponseWriter;
import io.github.jho951.platform.security.web.ReactiveSecurityFailureResponseWriter;
import io.github.jho951.platform.security.ratelimit.DefaultPlatformRateLimitAdapter;
import io.github.jho951.platform.security.ratelimit.DefaultBoundaryRateLimitPolicyProvider;
import io.github.jho951.platform.security.ratelimit.DefaultRateLimitKeyResolver;
import io.github.jho951.platform.security.ratelimit.PlatformRateLimitAdapter;
import io.github.jho951.ratelimiter.spi.RateLimiter;
import com.auth.apikey.ApiKeyAuthenticationProvider;
import com.auth.apikey.ApiKeyPrincipalResolver;
import com.auth.hmac.HmacAuthenticationProvider;
import com.auth.hmac.HmacPrincipalResolver;
import com.auth.hmac.HmacSecretResolver;
import com.auth.hmac.HmacSignatureVerifier;
import com.auth.hybrid.HybridAuthenticationProvider;
import com.auth.oidc.OidcAuthenticationProvider;
import com.auth.oidc.OidcPrincipalMapper;
import com.auth.oidc.OidcTokenVerifier;
import com.auth.serviceaccount.ServiceAccountAuthenticationProvider;
import com.auth.serviceaccount.ServiceAccountVerifier;
import com.auth.session.DefaultSessionAuthenticationProvider;
import com.auth.session.SessionPrincipalMapper;
import com.auth.session.SessionStore;
import com.auth.spi.OAuth2PrincipalResolver;
import com.auth.spi.TokenService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.server.WebFilter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * platform-security의 Spring Boot 자동 구성 진입점이다.
 *
 * <p>properties 바인딩, role preset 적용, core policy service, auth capability,
 * IP guard, rate limit, servlet/reactive filter, 운영 fail-fast guard를 조립한다.</p>
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "platform.security", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableMethodSecurity
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
        PlatformSecurityPresetApplier presetApplier = new PlatformSecurityPresetApplier();
        return new BeanPostProcessor() {
            @Override
            public Object postProcessAfterInitialization(Object bean, String beanName) {
                if (bean instanceof PlatformSecurityProperties properties) {
                    presetApplier.apply(properties);
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
    public PlatformIpRuleSourceFactory platformIpRuleSourceFactory(ResourceLoader resourceLoader) {
        return new SpringPlatformIpRuleSourceFactory(resourceLoader);
    }

    @Bean
    @ConditionalOnMissingBean
    public BoundaryIpPolicyProvider boundaryIpPolicyProvider(
            PlatformSecurityProperties properties,
            PlatformIpRuleSourceFactory ruleSourceFactory
    ) {
        return new DefaultBoundaryIpPolicyProvider(properties.getIpGuard(), ruleSourceFactory);
    }

    @Bean
    @ConditionalOnMissingBean
    public RateLimitKeyResolver rateLimitKeyResolver() {
        return new DefaultRateLimitKeyResolver();
    }

    @Bean
    @ConditionalOnBean(RateLimiter.class)
    @ConditionalOnMissingBean(PlatformRateLimitAdapter.class)
    public PlatformRateLimitAdapter platformRateLimitAdapter(RateLimiter rateLimiter) {
        return new DefaultPlatformRateLimitAdapter(rateLimiter);
    }

    @Bean
    @ConditionalOnBean(PlatformRateLimitAdapter.class)
    @ConditionalOnMissingBean
    public BoundaryRateLimitPolicyProvider boundaryRateLimitPolicyProvider(
            PlatformSecurityProperties properties,
            RateLimitKeyResolver rateLimitKeyResolver,
            PlatformRateLimitAdapter platformRateLimitAdapter
    ) {
        return new DefaultBoundaryRateLimitPolicyProvider(properties.getRateLimit(), rateLimitKeyResolver, platformRateLimitAdapter);
    }

    @Bean
    @ConditionalOnMissingBean(BoundaryRateLimitPolicyProvider.class)
    public BoundaryRateLimitPolicyProvider disabledBoundaryRateLimitPolicyProvider() {
        return new BoundaryRateLimitPolicyProvider() {
            @Override
            public io.github.jho951.platform.security.api.SecurityPolicy resolve(
                    io.github.jho951.platform.security.policy.SecurityBoundary boundary
            ) {
                return disabledPolicy();
            }

            @Override
            public io.github.jho951.platform.security.api.SecurityPolicy resolve(
                    io.github.jho951.platform.security.policy.SecurityBoundary boundary,
                    io.github.jho951.platform.security.api.ResolvedSecurityProfile profile
            ) {
                return disabledPolicy();
            }

            private io.github.jho951.platform.security.api.SecurityPolicy disabledPolicy() {
                return new io.github.jho951.platform.security.api.SecurityPolicy() {
                    @Override
                    public String name() {
                        return "rate-limiter";
                    }

                    @Override
                    public io.github.jho951.platform.security.api.SecurityVerdict evaluate(
                            io.github.jho951.platform.security.api.SecurityRequest request,
                            SecurityContext context
                    ) {
                        return io.github.jho951.platform.security.api.SecurityVerdict.allow(name(), "rate limit disabled; no PlatformRateLimitAdapter bean");
                    }
                };
            }
        };
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
    @ConditionalOnBean(HybridAuthenticationProvider.class)
    @ConditionalOnMissingBean({PlatformSessionSupport.class, PlatformSessionSupportFactory.class})
    public PlatformSessionSupportFactory platformSessionSupportFactoryFromHybridProvider(
            HybridAuthenticationProvider hybridAuthenticationProvider
    ) {
        return new DefaultPlatformSessionSupportFactory(hybridAuthenticationProvider);
    }

    @Bean
    @ConditionalOnBean({TokenService.class, SessionStore.class, SessionPrincipalMapper.class})
    @ConditionalOnMissingBean({PlatformSessionSupport.class, PlatformSessionSupportFactory.class})
    public PlatformSessionSupportFactory platformSessionSupportFactoryFromOssAuthBeans(
            TokenService tokenService,
            SessionStore sessionStore,
            SessionPrincipalMapper mapper
    ) {
        return new DefaultPlatformSessionSupportFactory(tokenService, sessionStore, mapper);
    }

    @Bean
    @ConditionalOnBean(PlatformSessionSupportFactory.class)
    @ConditionalOnMissingBean(PlatformSessionSupport.class)
    public PlatformSessionSupport platformSessionSupport(PlatformSessionSupportFactory platformSessionSupportFactory) {
        return platformSessionSupportFactory.create();
    }

    @Bean
    @ConditionalOnMissingBean(name = "jwtAuthenticationCapability")
    @ConditionalOnBean(PlatformSessionSupport.class)
    public AuthenticationCapability jwtAuthenticationCapability(PlatformSessionSupport platformSessionSupport) {
        return new DefaultJwtAuthenticationCapability(platformSessionSupport);
    }

    @Bean
    @ConditionalOnMissingBean(name = "sessionAuthenticationCapability")
    @ConditionalOnBean(PlatformSessionSupport.class)
    public AuthenticationCapability sessionAuthenticationCapability(PlatformSessionSupport platformSessionSupport) {
        return new DefaultSessionAuthenticationCapability(platformSessionSupport);
    }

    @Bean
    @ConditionalOnMissingBean(name = "hybridAuthenticationCapability")
    @ConditionalOnBean(PlatformSessionSupport.class)
    public AuthenticationCapability hybridAuthenticationCapability(PlatformSessionSupport platformSessionSupport) {
        return new DefaultHybridAuthenticationCapability(platformSessionSupport);
    }

    @Bean
    @ConditionalOnMissingBean(name = "internalAuthenticationCapability")
    @ConditionalOnBean({PlatformSessionSupport.class, InternalTokenClaimsValidator.class})
    public AuthenticationCapability internalAuthenticationCapability(
            PlatformSessionSupport platformSessionSupport,
            InternalTokenClaimsValidator internalTokenClaimsValidator
    ) {
        return new DefaultInternalServiceAuthenticationCapability(platformSessionSupport, internalTokenClaimsValidator);
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
    @ConditionalOnMissingBean(AuthenticationCapabilityResolver.class)
    public AuthenticationCapabilityResolver authenticationCapabilityResolver(
            @org.springframework.beans.factory.annotation.Qualifier("jwtAuthenticationCapability") ObjectProvider<AuthenticationCapability> jwtAuthenticationCapability,
            @org.springframework.beans.factory.annotation.Qualifier("sessionAuthenticationCapability") ObjectProvider<AuthenticationCapability> sessionAuthenticationCapability,
            @org.springframework.beans.factory.annotation.Qualifier("hybridAuthenticationCapability") ObjectProvider<AuthenticationCapability> hybridAuthenticationCapability,
            @org.springframework.beans.factory.annotation.Qualifier("internalAuthenticationCapability") ObjectProvider<AuthenticationCapability> internalAuthenticationCapability,
            @org.springframework.beans.factory.annotation.Qualifier("apiKeyAuthenticationCapability") ObjectProvider<AuthenticationCapability> apiKeyAuthenticationCapability,
            @org.springframework.beans.factory.annotation.Qualifier("hmacAuthenticationCapability") ObjectProvider<AuthenticationCapability> hmacAuthenticationCapability,
            @org.springframework.beans.factory.annotation.Qualifier("oidcAuthenticationCapability") ObjectProvider<AuthenticationCapability> oidcAuthenticationCapability,
            @org.springframework.beans.factory.annotation.Qualifier("serviceAccountAuthenticationCapability") ObjectProvider<AuthenticationCapability> serviceAccountAuthenticationCapability
    ) {
        return new DefaultAuthenticationCapabilityResolver(
                jwtAuthenticationCapability.getIfAvailable(),
                sessionAuthenticationCapability.getIfAvailable(),
                hybridAuthenticationCapability.getIfAvailable(),
                internalAuthenticationCapability.getIfAvailable(),
                apiKeyAuthenticationCapability.getIfAvailable(),
                hmacAuthenticationCapability.getIfAvailable(),
                oidcAuthenticationCapability.getIfAvailable(),
                serviceAccountAuthenticationCapability.getIfAvailable()
        );
    }

    @Bean
    @ConditionalOnMissingBean(SecurityContextResolver.class)
    @ConditionalOnClass(Authentication.class)
    public SecurityContextResolver springSecurityContextResolver() {
        return request -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            var attributes = new LinkedHashMap<>(request.attributes());
            if (authentication == null || !authentication.isAuthenticated()) {
                return new SecurityContext(false, null, Set.of(), attributes);
            }
            String principal = resolvePrincipal(authentication);
            Set<String> roles = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .filter(authority -> authority != null && !authority.isBlank())
                    .collect(Collectors.toUnmodifiableSet());
            return new SecurityContext(true, principal, roles, attributes);
        };
    }

    @Bean(name = "platformSecurityOperationalProfileResolver")
    @ConditionalOnMissingBean(OperationalProfileResolver.class)
    public OperationalProfileResolver platformSecurityOperationalProfileResolver() {
        return OperationalProfileResolver.standard();
    }

    @Bean
    public OperationalSecurityPolicyEnforcer operationalSecurityPolicyEnforcer(
            OperationalProfileResolver operationalProfileResolver
    ) {
        return new OperationalSecurityPolicyEnforcer(operationalProfileResolver);
    }

    @Bean
    public org.springframework.beans.factory.SmartInitializingSingleton platformSecurityOperationalPolicyGuard(
            PlatformSecurityProperties properties,
            OperationalSecurityPolicyEnforcer enforcer,
            ObjectProvider<SecurityContextResolver> resolverProvider,
            Environment environment,
            ApplicationContext applicationContext
    ) {
        return () -> {
            enforcer.enforce(
                    properties,
                    resolverProvider.getIfAvailable() != null,
                    applicationContext.containsBean("platformSecurityLocalTokenIssuerPort"),
                    applicationContext.containsBean("platformSecurityLocalSessionIssuerPort"),
                    !applicationContext.getBeansOfType(PlatformRateLimitAdapter.class).isEmpty(),
                    !applicationContext.getBeansOfType(PlatformTokenIssuerPort.class).isEmpty(),
                    !applicationContext.getBeansOfType(PlatformSessionIssuerPort.class).isEmpty(),
                    applicationContext.containsBean("platformSecurityLocalRateLimitAdapter"),
                    applicationContext.containsBean("platformSecurityLocalInternalTokenClaimsValidator"),
                    environment.getActiveProfiles()
            );
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
    @ConditionalOnMissingBean({PlatformSecurityServletFilter.class, PlatformSecurityHybridWebAdapterMarker.class})
    @ConditionalOnBean(SecurityContextResolver.class)
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
    @ConditionalOnBean(PlatformSecurityServletFilter.class)
    @ConditionalOnMissingBean(PlatformSecurityHybridWebAdapterMarker.class)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    public FilterRegistrationBean<PlatformSecurityServletFilter> platformSecurityServletFilterRegistration(
            PlatformSecurityServletFilter filter
    ) {
        FilterRegistrationBean<PlatformSecurityServletFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    @ConditionalOnClass(WebFilter.class)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
    @ConditionalOnMissingBean({PlatformSecurityWebFilter.class, PlatformSecurityHybridWebAdapterMarker.class})
    @ConditionalOnBean(SecurityContextResolver.class)
    public WebFilter securityWebFilter(
            SecurityIngressAdapter securityIngressAdapter,
            SecurityContextResolver securityContextResolver,
            SecurityIngressRequestFactory securityIngressRequestFactory,
            SecurityDownstreamIdentityPropagator downstreamIdentityPropagator,
            SecurityAuditPublisher securityAuditPublisher,
            ReactiveSecurityFailureResponseWriter failureResponseWriter
    ) {
        return new PlatformSecurityWebFilter(
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
    @ConditionalOnClass(name = "jakarta.servlet.http.HttpServletResponse")
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    public SecurityFailureResponseWriter securityFailureResponseWriter() {
        return SecurityFailureResponseWriter.json();
    }

    @Bean
    @ConditionalOnMissingBean({AuthenticationEntryPoint.class, PlatformSecurityHybridWebAdapterMarker.class})
    @ConditionalOnClass(AuthenticationEntryPoint.class)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    public AuthenticationEntryPoint platformAuthenticationEntryPoint(
            SecurityFailureResponseWriter failureResponseWriter
    ) {
        return (request, response, authException) -> failureResponseWriter.write(
                request,
                response,
                new SecurityFailureResponse(401, "security.auth.required", exceptionMessage(authException))
        );
    }

    @Bean
    @ConditionalOnMissingBean({AccessDeniedHandler.class, PlatformSecurityHybridWebAdapterMarker.class})
    @ConditionalOnClass(AccessDeniedHandler.class)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    public AccessDeniedHandler platformAccessDeniedHandler(
            SecurityFailureResponseWriter failureResponseWriter
    ) {
        return (request, response, accessDeniedException) -> failureResponseWriter.write(
                request,
                response,
                new SecurityFailureResponse(403, "security.denied", exceptionMessage(accessDeniedException))
        );
    }

    @Bean
    @ConditionalOnMissingBean(JwtDecoder.class)
    @ConditionalOnClass({JwtDecoder.class, NimbusJwtDecoder.class})
    public JwtDecoder platformSecurityJwtDecoder(PlatformSecurityProperties properties) {
        PlatformSecurityProperties.AuthProperties auth = properties.getAuth();
        SecretKey secretKey = new SecretKeySpec(auth.getJwtSecret().getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(secretKey).build();
        decoder.setJwtValidator(jwtValidator(auth));
        return decoder;
    }

    @Bean
    @ConditionalOnMissingBean(JwtAuthenticationConverter.class)
    @ConditionalOnClass(JwtAuthenticationConverter.class)
    public JwtAuthenticationConverter platformSecurityJwtAuthenticationConverter(PlatformSecurityProperties properties) {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new PlatformJwtAuthorityConverter(properties.getAuth()));
        converter.setPrincipalClaimName(properties.getAuth().getJwtPrincipalClaim());
        return converter;
    }

    @Bean
    @ConditionalOnMissingBean({GatewayHeaderAuthenticationFilter.class, PlatformSecurityHybridWebAdapterMarker.class})
    @ConditionalOnClass(name = "jakarta.servlet.Filter")
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    public GatewayHeaderAuthenticationFilter gatewayHeaderAuthenticationFilter(PlatformSecurityProperties properties) {
        return new GatewayHeaderAuthenticationFilter(properties.getAuth().getGatewayHeader());
    }

    @Bean
    @ConditionalOnBean(GatewayHeaderAuthenticationFilter.class)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    @ConditionalOnMissingBean(PlatformSecurityHybridWebAdapterMarker.class)
    public FilterRegistrationBean<GatewayHeaderAuthenticationFilter> gatewayHeaderAuthenticationFilterRegistration(
            GatewayHeaderAuthenticationFilter filter
    ) {
        FilterRegistrationBean<GatewayHeaderAuthenticationFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnClass(name = {
            "org.springframework.web.server.ServerWebExchange",
            "reactor.core.publisher.Mono"
    })
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
    public ReactiveSecurityFailureResponseWriter reactiveSecurityFailureResponseWriter() {
        return ReactiveSecurityFailureResponseWriter.json();
    }


    @Bean
    @ConditionalOnMissingBean({SecurityFilterChain.class, PlatformSecurityHybridWebAdapterMarker.class})
    @ConditionalOnBean(PlatformSecurityServletFilter.class)
    @ConditionalOnClass({SecurityFilterChain.class, HttpSecurity.class, BearerTokenAuthenticationFilter.class})
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    public SecurityFilterChain platformSecurityFilterChain(
            HttpSecurity http,
            PlatformSecurityProperties properties,
            PlatformSecurityServletFilter platformSecurityServletFilter,
            ObjectProvider<GatewayHeaderAuthenticationFilter> gatewayHeaderAuthenticationFilterProvider,
            ObjectProvider<JwtDecoder> jwtDecoderProvider,
            ObjectProvider<JwtAuthenticationConverter> jwtAuthenticationConverterProvider,
            ObjectProvider<AuthenticationEntryPoint> authenticationEntryPointProvider,
            ObjectProvider<AccessDeniedHandler> accessDeniedHandlerProvider
    ) throws Exception {
        http
                .cors(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(exceptions -> {
                    AuthenticationEntryPoint entryPoint = authenticationEntryPointProvider.getIfAvailable();
                    AccessDeniedHandler deniedHandler = accessDeniedHandlerProvider.getIfAvailable();
                    if (entryPoint != null) {
                        exceptions.authenticationEntryPoint(entryPoint);
                    }
                    if (deniedHandler != null) {
                        exceptions.accessDeniedHandler(deniedHandler);
                    }
                })
                .authorizeHttpRequests(auth -> {
                    requestMatchers(auth, publicPaths(properties), AuthorizationRule.PERMIT_ALL);
                    requestMatchers(auth, properties.getBoundary().getProtectedPaths(), AuthorizationRule.AUTHENTICATED);
                    requestMatchers(auth, properties.getBoundary().getAdminPaths(), AuthorizationRule.AUTHENTICATED);
                    requestMatchers(auth, properties.getBoundary().getInternalPaths(), AuthorizationRule.INTERNAL_AUTHORITY, properties);
                    auth.anyRequest().denyAll();
                });

        GatewayHeaderAuthenticationFilter gatewayHeaderAuthenticationFilter = gatewayHeaderAuthenticationFilterProvider.getIfAvailable();
        if (gatewayHeaderAuthenticationFilter != null) {
            http.addFilterAfter(gatewayHeaderAuthenticationFilter, BearerTokenAuthenticationFilter.class);
            http.addFilterAfter(platformSecurityServletFilter, GatewayHeaderAuthenticationFilter.class);
        } else {
            http.addFilterAfter(platformSecurityServletFilter, BearerTokenAuthenticationFilter.class);
        }

        JwtDecoder jwtDecoder = jwtDecoderProvider.getIfAvailable();
        if (jwtDecoder != null) {
            http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> {
                jwt.decoder(jwtDecoder);
                JwtAuthenticationConverter converter = jwtAuthenticationConverterProvider.getIfAvailable();
                if (converter != null) {
                    jwt.jwtAuthenticationConverter(converter);
                }
            }));
        }

        return http.build();
    }

    private static OAuth2TokenValidator<Jwt> jwtValidator(PlatformSecurityProperties.AuthProperties auth) {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        String issuer = trimToNull(auth.getJwtIssuer());
        if (issuer == null) {
            validators.add(JwtValidators.createDefault());
        } else {
            validators.add(JwtValidators.createDefaultWithIssuer(issuer));
        }

        String audience = trimToNull(auth.getJwtAudience());
        if (audience != null) {
            validators.add(jwt -> {
                List<String> audiences = jwt.getAudience();
                if (audiences != null && audiences.contains(audience)) {
                    return OAuth2TokenValidatorResult.success();
                }
                return OAuth2TokenValidatorResult.failure(
                        new OAuth2Error("invalid_token", "aud claim does not include required audience", null)
                );
            });
        }

        if (auth.isJwtRequireSubject()) {
            validators.add(jwt -> {
                String subject = jwt.getSubject();
                if (subject != null && !subject.isBlank()) {
                    return OAuth2TokenValidatorResult.success();
                }
                return OAuth2TokenValidatorResult.failure(
                        new OAuth2Error("invalid_token", "sub claim is required", null)
                );
            });
        }

        return new DelegatingOAuth2TokenValidator<>(validators);
    }

    private static String exceptionMessage(Exception exception) {
        return exception == null ? null : exception.getMessage();
    }

    private static void requestMatchers(
            org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry auth,
            List<String> paths,
            AuthorizationRule rule
    ) {
        requestMatchers(auth, paths, rule, null);
    }

    private static void requestMatchers(
            org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry auth,
            List<String> paths,
            AuthorizationRule rule,
            PlatformSecurityProperties properties
    ) {
        List<String> normalizedPaths = normalizePaths(paths);
        if (normalizedPaths.isEmpty()) {
            return;
        }
        var matcher = auth.requestMatchers(normalizedPaths.toArray(String[]::new));
        if (rule == AuthorizationRule.PERMIT_ALL) {
            matcher.permitAll();
            return;
        }
        if (rule == AuthorizationRule.INTERNAL_AUTHORITY && properties != null) {
            List<String> authorities = normalizePaths(properties.getAuth().getInternalRequiredAuthorities());
            if (!authorities.isEmpty()) {
                matcher.hasAnyAuthority(authorities.toArray(String[]::new));
                return;
            }
        }
        matcher.authenticated();
    }

    private static List<String> publicPaths(PlatformSecurityProperties properties) {
        return normalizePaths(properties.getBoundary().getPublicPaths());
    }

    private static List<String> normalizePaths(List<String> paths) {
        if (paths == null) {
            return List.of();
        }
        return paths.stream()
                .filter(path -> path != null && !path.isBlank())
                .map(String::trim)
                .distinct()
                .toList();
    }

    private static String trimToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }

    private static String resolvePrincipal(Authentication authentication) {
        if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
            Jwt token = jwtAuthenticationToken.getToken();
            if (token.getSubject() != null && !token.getSubject().isBlank()) {
                return token.getSubject();
            }
        }
        String name = authentication.getName();
        return name == null || name.isBlank() ? null : name;
    }

    private enum AuthorizationRule {
        PERMIT_ALL,
        AUTHENTICATED,
        INTERNAL_AUTHORITY
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
