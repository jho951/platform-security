package io.github.jho951.platform.security.auth.autoconfigure;

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
import com.auth.session.IdentitySessionPrincipalMapper;
import com.auth.session.SessionPrincipalMapper;
import com.auth.session.SessionStore;
import com.auth.spi.OAuth2PrincipalResolver;
import com.auth.spi.TokenService;
import io.github.jho951.platform.security.auth.AuthenticationCapability;
import io.github.jho951.platform.security.auth.DefaultApiKeyAuthenticationCapability;
import io.github.jho951.platform.security.auth.DefaultHmacAuthenticationCapability;
import io.github.jho951.platform.security.auth.DefaultOAuth2PrincipalBridge;
import io.github.jho951.platform.security.auth.DefaultOidcAuthenticationCapability;
import io.github.jho951.platform.security.auth.DefaultOidcPrincipalMapper;
import io.github.jho951.platform.security.auth.DefaultPlatformSessionSupportFactory;
import io.github.jho951.platform.security.auth.DefaultServiceAccountAuthenticationCapability;
import io.github.jho951.platform.security.auth.OAuth2PrincipalBridge;
import io.github.jho951.platform.security.auth.PlatformSessionIssuerPort;
import io.github.jho951.platform.security.auth.PlatformSessionSupportFactory;
import io.github.jho951.platform.security.auth.PlatformTokenIssuerPort;
import io.github.jho951.platform.security.auth.SessionStorePlatformSessionIssuerPort;
import io.github.jho951.platform.security.auth.TokenServicePlatformTokenIssuerPort;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

/**
 * optional bridge starter가 auth 1계층 bean graph를 platform-owned port/capability로 연결하는 adapter auto-configuration이다.
 * base starter는 이 auto-configuration을 직접 가져오지 않는다.
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "platform.security", name = "enabled", havingValue = "true", matchIfMissing = true)
public class PlatformSecurityAuthAdapterAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(SessionPrincipalMapper.class)
    public SessionPrincipalMapper platformSessionPrincipalMapper() {
        return new IdentitySessionPrincipalMapper();
    }

    @Bean
    @ConditionalOnBean(HybridAuthenticationProvider.class)
    @ConditionalOnMissingBean(PlatformSessionSupportFactory.class)
    public PlatformSessionSupportFactory platformSessionSupportFactoryFromHybridProvider(
            HybridAuthenticationProvider hybridAuthenticationProvider
    ) {
        return new DefaultPlatformSessionSupportFactory(hybridAuthenticationProvider);
    }

    @Bean
    @ConditionalOnBean({TokenService.class, SessionStore.class, SessionPrincipalMapper.class})
    @ConditionalOnMissingBean(PlatformSessionSupportFactory.class)
    public PlatformSessionSupportFactory platformSessionSupportFactoryFromAuthBeans(
            TokenService tokenService,
            SessionStore sessionStore,
            SessionPrincipalMapper mapper
    ) {
        return new DefaultPlatformSessionSupportFactory(tokenService, sessionStore, mapper);
    }

    @Bean
    @ConditionalOnBean(TokenService.class)
    @ConditionalOnMissingBean(PlatformTokenIssuerPort.class)
    public PlatformTokenIssuerPort platformTokenIssuerPort(TokenService tokenService) {
        return new TokenServicePlatformTokenIssuerPort(tokenService);
    }

    @Bean
    @ConditionalOnBean(SessionStore.class)
    @ConditionalOnMissingBean(PlatformSessionIssuerPort.class)
    public PlatformSessionIssuerPort platformSessionIssuerPort(SessionStore sessionStore) {
        return new SessionStorePlatformSessionIssuerPort(sessionStore);
    }

    @Bean
    @ConditionalOnMissingBean(ApiKeyAuthenticationProvider.class)
    @ConditionalOnBean(ApiKeyPrincipalResolver.class)
    public ApiKeyAuthenticationProvider apiKeyAuthenticationProvider(ApiKeyPrincipalResolver resolver) {
        return new ApiKeyAuthenticationProvider(resolver);
    }

    @Bean(name = "apiKeyAuthenticationCapability")
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

    @Bean(name = "hmacAuthenticationCapability")
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

    @Bean(name = "oidcAuthenticationCapability")
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

    @Bean(name = "serviceAccountAuthenticationCapability")
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
}
