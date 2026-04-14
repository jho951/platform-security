package io.github.jho951.platform.security.issuer.starter;

import io.github.jho951.platform.security.policy.ServiceRolePreset;
import io.github.jho951.platform.security.policy.ServiceRolePresetProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class PlatformSecurityIssuerStarterAutoConfiguration {
    @Bean
    public ServiceRolePresetProvider issuerServiceRolePresetProvider() {
        return () -> ServiceRolePreset.ISSUER;
    }
}
