package io.github.jho951.platform.security.ratelimit;

import io.github.jho951.ratelimiter.core.RateLimitDecision;
import io.github.jho951.ratelimiter.core.RateLimitKey;
import io.github.jho951.ratelimiter.core.RateLimitKeyType;
import io.github.jho951.ratelimiter.core.RateLimitPlan;
import io.github.jho951.ratelimiter.spi.RateLimiter;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

/**
 * Redis fixed-window {@link RateLimiter} implementation for distributed platform rate limiting.
 */
public final class RedisFixedWindowRateLimiter implements RateLimiter {
    private final StringRedisTemplate redisTemplate;
    private final String keyPrefix;
    private final Clock clock;

    public RedisFixedWindowRateLimiter(
            StringRedisTemplate redisTemplate,
            String keyPrefix,
            Clock clock
    ) {
        this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate");
        this.keyPrefix = keyPrefix == null ? "" : keyPrefix;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public RateLimitDecision tryAcquire(RateLimitKey key, long permits, RateLimitPlan plan) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(plan, "plan");

        long requestedPermits = Math.max(1L, permits);
        long limit = Math.max(1L, plan.getCapacity());
        long windowSeconds = resolveWindowSeconds(plan);
        long nowSeconds = clock.instant().getEpochSecond();
        long windowIndex = nowSeconds / windowSeconds;
        long windowEndSeconds = (windowIndex + 1L) * windowSeconds;
        String redisKey = keyPrefix
                + keyTypeSegment(key.getType())
                + ":"
                + key.getValue()
                + ":"
                + windowIndex;

        Long current = redisTemplate.opsForValue().increment(redisKey, requestedPermits);
        if (current == null) {
            return RateLimitDecision.deny(0L, 1000L);
        }
        if (current == requestedPermits) {
            redisTemplate.expire(redisKey, Duration.ofSeconds(windowSeconds + 1L));
        }
        if (current <= limit) {
            return RateLimitDecision.allow(Math.max(0L, limit - current));
        }

        long retryAfterMillis = Math.max(0L, (windowEndSeconds - nowSeconds) * 1000L);
        return RateLimitDecision.deny(Math.max(0L, limit - current), retryAfterMillis);
    }

    private long resolveWindowSeconds(RateLimitPlan plan) {
        double refillTokensPerSecond = plan.getRefillTokensPerSecond();
        if (refillTokensPerSecond <= 0d) {
            return 1L;
        }
        double seconds = plan.getCapacity() / refillTokensPerSecond;
        if (!Double.isFinite(seconds) || seconds <= 0d) {
            return 1L;
        }
        return Math.max(1L, (long) Math.ceil(seconds));
    }

    private String keyTypeSegment(RateLimitKeyType keyType) {
        if (keyType == RateLimitKeyType.USER_ID) {
            return "user";
        }
        if (keyType == RateLimitKeyType.API_KEY) {
            return "api-key";
        }
        return "ip";
    }
}
