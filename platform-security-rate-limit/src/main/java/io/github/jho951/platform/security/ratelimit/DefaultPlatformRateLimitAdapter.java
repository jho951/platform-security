package io.github.jho951.platform.security.ratelimit;

import io.github.jho951.ratelimiter.spi.RateLimiter;
import io.github.jho951.ratelimiter.core.RateLimitDecision;
import io.github.jho951.ratelimiter.core.RateLimitKey;
import io.github.jho951.ratelimiter.core.RateLimitKeyType;
import io.github.jho951.ratelimiter.core.RateLimitPlan;

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
    public PlatformRateLimitDecision evaluate(PlatformRateLimitRequest request) {
        Objects.requireNonNull(request, "request");
        RateLimitKeyType keyType = request.keyType() == PlatformRateLimitKeyType.USER
                ? RateLimitKeyType.USER_ID
                : RateLimitKeyType.IP;
        RateLimitKey key = RateLimitKey.of(keyType, request.key());
        double refillPerSecond = (double) request.limit() / (double) request.windowSeconds();
        RateLimitPlan plan = RateLimitPlan.perSecond(request.limit(), refillPerSecond);
        RateLimitDecision decision = rateLimiter.tryAcquire(key, request.permits(), plan);
        if (decision.isAllowed()) {
            return PlatformRateLimitDecision.allow(request.key(), "within rate limit");
        }
        return PlatformRateLimitDecision.deny(request.key(), "rate limit exceeded for " + request.key());
    }
}
