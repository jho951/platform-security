package io.github.jho951.platform.security.ratelimit.autoconfigure;

import io.github.jho951.platform.security.ratelimit.DefaultPlatformRateLimitAdapter;
import io.github.jho951.platform.security.ratelimit.PlatformRateLimitPort;
import io.github.jho951.ratelimiter.spi.RateLimiter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

/**
 * rate-limiter 1계층 구현을 platform-owned adapter로 연결하는 auto-configuration이다.
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "platform.security", name = "enabled", havingValue = "true", matchIfMissing = true)
public class PlatformSecurityRateLimitAdapterAutoConfiguration {

    @Bean
    @ConditionalOnBean(RateLimiter.class)
    @ConditionalOnMissingBean(PlatformRateLimitPort.class)
    public PlatformRateLimitPort platformRateLimitPort(RateLimiter rateLimiter) {
        return new DefaultPlatformRateLimitAdapter(rateLimiter);
    }
}
