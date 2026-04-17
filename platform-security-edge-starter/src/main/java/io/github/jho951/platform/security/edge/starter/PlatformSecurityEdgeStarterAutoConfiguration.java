package io.github.jho951.platform.security.edge.starter;

import io.github.jho951.platform.security.policy.ServiceRolePreset;
import io.github.jho951.platform.security.policy.ServiceRolePresetProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;

/**
 * edge service role preset을 platform-security auto-configuration에 전달한다.
 */
@AutoConfiguration
public class PlatformSecurityEdgeStarterAutoConfiguration {
    @Bean
    public ServiceRolePresetProvider edgeServiceRolePresetProvider() {
        return () -> ServiceRolePreset.EDGE;
    }
}
