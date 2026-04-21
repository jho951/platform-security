package io.github.jho951.platform.security.ratelimit;

import io.github.jho951.ratelimiter.spi.RateLimiter;

import java.util.Objects;

/**
 * 기본 platform rate-limit adapter다.
 */
public class DefaultPlatformRateLimitAdapter implements PlatformRateLimitAdapter {
    private final RateLimiter rateLimiter;

    public DefaultPlatformRateLimitAdapter(RateLimiter rateLimiter) {
        this.rateLimiter = Objects.requireNonNull(rateLimiter, "rateLimiter");
    }

    @Override
    public RateLimiter rateLimiter() {
        return rateLimiter;
    }
}
