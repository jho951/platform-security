package io.github.jho951.platform.security.ratelimit;

import io.github.jho951.ratelimiter.spi.RateLimiter;

/**
 * 1계층 RateLimiter를 platform 소유 경계로 감싼 adapter다.
 */
public interface PlatformRateLimitAdapter {

    RateLimiter rateLimiter();
}
