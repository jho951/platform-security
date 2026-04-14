package io.github.jho951.platform.security.internal.starter;

import io.github.jho951.platform.security.policy.ServiceRolePreset;
import io.github.jho951.platform.security.policy.ServiceRolePresetProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class PlatformSecurityInternalServiceStarterAutoConfiguration {
    @Bean
    public ServiceRolePresetProvider internalServiceRolePresetProvider() {
        return () -> ServiceRolePreset.INTERNAL_SERVICE;
    }
}
