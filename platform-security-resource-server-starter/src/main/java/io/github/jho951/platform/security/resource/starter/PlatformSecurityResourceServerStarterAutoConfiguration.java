package io.github.jho951.platform.security.resource.starter;

import io.github.jho951.platform.security.policy.ServiceRolePreset;
import io.github.jho951.platform.security.policy.ServiceRolePresetProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class PlatformSecurityResourceServerStarterAutoConfiguration {
    @Bean
    public ServiceRolePresetProvider resourceServerServiceRolePresetProvider() {
        return () -> ServiceRolePreset.RESOURCE_SERVER;
    }
}
