package io.github.jho951.platform.security.local;

import com.auth.hybrid.DefaultHybridAuthenticationProvider;
import com.auth.hybrid.HybridAuthenticationProvider;
import com.auth.session.DefaultSessionAuthenticationProvider;
import com.auth.session.IdentitySessionPrincipalMapper;
import com.auth.session.SessionPrincipalMapper;
import com.auth.session.SessionStore;
import com.auth.session.SimpleSessionStore;
import com.auth.spi.TokenService;
import com.auth.support.jwt.JwtTokenService;
import io.github.jho951.platform.security.api.SecurityContextResolver;
import io.github.jho951.platform.security.auth.InternalTokenClaimsValidator;
import io.github.jho951.platform.security.auth.PlatformAuthenticationFacade;
import io.github.jho951.platform.security.core.limiter.InMemoryRateLimiter;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.ratelimiter.spi.RateLimiter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

import java.time.Clock;

/**
 * local/test에서만 명시적으로 opt-in하는 fallback bean graph다.
 */
@AutoConfiguration
@AutoConfigureBefore(name = "io.github.jho951.platform.security.autoconfigure.PlatformSecurityAutoConfiguration")
@ConditionalOnProperty(prefix = "platform.security.local-support", name = "enabled", havingValue = "true")
public class PlatformSecurityLocalSupportAutoConfiguration {
    @Bean
    @ConditionalOnMissingBean(TokenService.class)
    public TokenService platformSecurityLocalTokenService(PlatformSecurityProperties properties) {
        PlatformSecurityProperties.AuthProperties auth = properties.getAuth();
        return new JwtTokenService(
                auth.getJwtSecret(),
                auth.getAccessTokenTtl().toSeconds(),
                auth.getRefreshTokenTtl().toSeconds()
        );
    }

    @Bean
    @ConditionalOnMissingBean(SessionStore.class)
    public SessionStore platformSecurityLocalSessionStore() {
        return new SimpleSessionStore();
    }

    @Bean
    @ConditionalOnMissingBean(SessionPrincipalMapper.class)
    public SessionPrincipalMapper platformSecurityLocalSessionPrincipalMapper() {
        return new IdentitySessionPrincipalMapper();
    }

    @Bean
    @ConditionalOnMissingBean(HybridAuthenticationProvider.class)
    public HybridAuthenticationProvider platformSecurityLocalHybridAuthenticationProvider(
            TokenService tokenService,
            SessionStore sessionStore,
            SessionPrincipalMapper sessionPrincipalMapper
    ) {
        return new DefaultHybridAuthenticationProvider(
                tokenService,
                new DefaultSessionAuthenticationProvider(sessionStore, sessionPrincipalMapper)
        );
    }

    @Bean
    @ConditionalOnMissingBean(RateLimiter.class)
    public RateLimiter platformSecurityLocalRateLimiter() {
        return new InMemoryRateLimiter(Clock.systemUTC());
    }

    @Bean
    @ConditionalOnMissingBean(InternalTokenClaimsValidator.class)
    public InternalTokenClaimsValidator platformSecurityLocalInternalTokenClaimsValidator() {
        return new LocalInternalTokenClaimsValidator();
    }

    @Bean
    @ConditionalOnMissingBean(SecurityContextResolver.class)
    @ConditionalOnProperty(prefix = "platform.security.auth.dev-fallback", name = "enabled", havingValue = "true")
    public SecurityContextResolver platformSecurityLocalDevFallbackSecurityContextResolver(
            HybridAuthenticationProvider hybridAuthenticationProvider,
            InternalTokenClaimsValidator internalTokenClaimsValidator
    ) {
        return new PlatformAuthenticationFacade(hybridAuthenticationProvider, internalTokenClaimsValidator);
    }
}
