package io.github.jho951.platform.security.hybrid;

import io.github.jho951.platform.security.api.PlatformSecurityHybridWebAdapterMarker;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;

/**
 * platform-security의 기본 web filter/chain auto-registration을 끄고,
 * 안전한 core/web 조립 bean만 남기는 hybrid adapter 모드다.
 */
@AutoConfiguration
@AutoConfigureBefore(name = "io.github.jho951.platform.security.autoconfigure.PlatformSecurityAutoConfiguration")
public class PlatformSecurityHybridWebAdapterAutoConfiguration {

    @Bean
    public PlatformSecurityHybridWebAdapterMarker platformSecurityHybridWebAdapterMarker() {
        return new PlatformSecurityHybridWebAdapterMarker() {
        };
    }
}
