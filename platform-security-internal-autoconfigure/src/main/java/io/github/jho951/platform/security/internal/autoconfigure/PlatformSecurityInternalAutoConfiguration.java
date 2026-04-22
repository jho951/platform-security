package io.github.jho951.platform.security.internal.autoconfigure;

import io.github.jho951.platform.security.auth.InternalTokenClaimsValidator;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

/**
 * internal-service role에서 필요한 internal token 계약을 검증한다.
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "platform.security", name = "enabled", havingValue = "true", matchIfMissing = true)
public class PlatformSecurityInternalAutoConfiguration {
    @Bean
    public SmartInitializingSingleton platformSecurityInternalValidatorGuard(
            PlatformSecurityProperties properties,
            ObjectProvider<InternalTokenClaimsValidator> validatorProvider,
            ApplicationContext applicationContext
    ) {
        return () -> {
            if (properties.getAuth().isInternalTokenEnabled()
                    && validatorProvider.getIfAvailable() == null
                    && !hasSpringSecurityJwtDecoder(applicationContext)) {
                throw new IllegalStateException(
                        "Internal service authentication requires an InternalTokenClaimsValidator bean or a Spring Security JwtDecoder bean. " +
                                "Provide a service-specific validator, configure resource-server JWT, or add platform-security-support-local for local/test."
                );
            }
        };
    }

    private boolean hasSpringSecurityJwtDecoder(ApplicationContext applicationContext) {
        try {
            Class<?> jwtDecoderType = Class.forName("org.springframework.security.oauth2.jwt.JwtDecoder");
            return applicationContext.getBeanNamesForType(jwtDecoderType, false, false).length > 0;
        }
        catch (ClassNotFoundException ignored) {
            return false;
        }
    }
}
