package io.github.jho951.platform.security.resource.starter;

import io.github.jho951.platform.security.policy.ServiceRolePreset;
import io.github.jho951.platform.security.policy.ServiceRolePresetProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;

/**
 * resource-server service role preset을 platform-security auto-configuration에 전달한다.
 */
@AutoConfiguration
public class PlatformSecurityResourceServerStarterAutoConfiguration {
    @Bean
    public ServiceRolePresetProvider resourceServerServiceRolePresetProvider() {
        return () -> ServiceRolePreset.RESOURCE_SERVER;
    }
}
