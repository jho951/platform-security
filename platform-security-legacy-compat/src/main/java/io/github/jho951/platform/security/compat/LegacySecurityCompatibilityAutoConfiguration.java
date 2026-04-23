package io.github.jho951.platform.security.compat;

import io.github.jho951.platform.security.auth.InternalServiceCompatibilityAuthenticationAdapter;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.web.SecurityRequestAttributeContributor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

/**
 * legacy shared-secret ingress compatibility를 별도 add-on으로 제공한다.
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "platform.security.auth.legacy-secret", name = "enabled", havingValue = "true")
public class LegacySecurityCompatibilityAutoConfiguration {
    @Bean
    @ConditionalOnMissingBean(name = "legacySecretSecurityRequestAttributeContributor")
    public SecurityRequestAttributeContributor legacySecretSecurityRequestAttributeContributor() {
        return new LegacySecretSecurityRequestAttributeContributor();
    }

    @Bean
    @ConditionalOnMissingBean(name = "legacySecretInternalServiceCompatibilityAuthenticationAdapter")
    public InternalServiceCompatibilityAuthenticationAdapter legacySecretInternalServiceCompatibilityAuthenticationAdapter(
            PlatformSecurityProperties properties
    ) {
        return new LegacySecretInternalServiceCompatibilityAuthenticationAdapter(properties.getAuth().getLegacySecret());
    }
}
