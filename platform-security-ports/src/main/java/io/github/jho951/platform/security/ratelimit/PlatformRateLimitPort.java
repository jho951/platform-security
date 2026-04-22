package io.github.jho951.platform.security.ratelimit;

/**
 * platform-owned request/decision 계약으로 rate limit 판단을 수행하는 port다.
 */
public interface PlatformRateLimitPort {

    PlatformRateLimitDecision evaluate(PlatformRateLimitRequest request);
}
