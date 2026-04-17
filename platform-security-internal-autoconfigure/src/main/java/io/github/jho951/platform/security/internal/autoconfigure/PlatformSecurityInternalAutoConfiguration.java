package io.github.jho951.platform.security.internal.autoconfigure;

import io.github.jho951.platform.security.auth.InternalTokenClaimsValidator;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
            ObjectProvider<InternalTokenClaimsValidator> validatorProvider
    ) {
        return () -> {
            if (properties.getAuth().isInternalTokenEnabled() && validatorProvider.getIfAvailable() == null) {
                throw new IllegalStateException(
                        "Internal service authentication requires an InternalTokenClaimsValidator bean. " +
                                "Provide a service-specific validator or add platform-security-local-support for local/test."
                );
            }
        };
    }
}
