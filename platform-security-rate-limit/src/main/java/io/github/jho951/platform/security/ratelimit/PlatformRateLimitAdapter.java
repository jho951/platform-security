package io.github.jho951.platform.security.ratelimit;

/**
 * 1계층 RateLimiter를 platform 소유 decision 계약으로 감싼 adapter다.
 */
public interface PlatformRateLimitAdapter {

    PlatformRateLimitDecision evaluate(PlatformRateLimitRequest request);
}
