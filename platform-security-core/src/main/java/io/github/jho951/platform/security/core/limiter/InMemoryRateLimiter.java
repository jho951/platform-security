package io.github.jho951.platform.security.core.limiter;

import io.github.jho951.ratelimiter.core.RateLimitDecision;
import io.github.jho951.ratelimiter.core.RateLimitKey;
import io.github.jho951.ratelimiter.core.RateLimitPlan;
import io.github.jho951.ratelimiter.spi.RateLimiter;

import java.time.Clock;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

public final class InMemoryRateLimiter implements RateLimiter {
    private final Clock clock;
    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

	private void refill(Bucket bucket, RateLimitPlan plan) {
		long now = clock.millis();
		long elapsedMillis = Math.max(0L, now - bucket.lastRefillMillis);
		if (elapsedMillis <= 0L) return;

		double refillRatePerSecond = plan.getRefillTokensPerSecond();
		double added = (elapsedMillis / 1000.0d) * refillRatePerSecond;
		if (added > 0d) {
			bucket.tokens = Math.min(plan.getCapacity(), bucket.tokens + (long) Math.floor(added));
			bucket.lastRefillMillis = now;
		}
	}

	private long computeRetryAfterMillis(Bucket bucket, RateLimitPlan plan, long requested) {
		long deficit = requested - bucket.tokens;
		double refillRatePerSecond = plan.getRefillTokensPerSecond();
		if (refillRatePerSecond <= 0d) return 1000L;
		return (long) Math.ceil((deficit / refillRatePerSecond) * 1000d);
	}

	private static final class Bucket {
		private long tokens;
		private long lastRefillMillis;

		private Bucket(long capacity, long now) {
			this.tokens = capacity;
			this.lastRefillMillis = now;
		}
	}

    public InMemoryRateLimiter() {
        this(Clock.systemUTC());
    }

    public InMemoryRateLimiter(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public RateLimitDecision tryAcquire(RateLimitKey key, long permits, RateLimitPlan plan) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(plan, "plan");
        long requested = Math.max(1L, permits);
        String bucketKey = key.asString();
        Bucket bucket = buckets.computeIfAbsent(bucketKey, ignored -> new Bucket(plan.getCapacity(), clock.millis()));

        synchronized (bucket) {
            refill(bucket, plan);
            if (bucket.tokens >= requested) {
                bucket.tokens -= requested;
                return RateLimitDecision.allow(bucket.tokens);
            }
            long retryAfterMillis = computeRetryAfterMillis(bucket, plan, requested);
            return RateLimitDecision.deny(bucket.tokens, retryAfterMillis);
        }
    }
}
