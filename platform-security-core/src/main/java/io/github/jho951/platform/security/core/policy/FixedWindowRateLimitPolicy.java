package io.github.jho951.platform.security.core.policy;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.policy.SecurityAttributes;
import io.github.jho951.ratelimiter.core.RateLimitDecision;
import io.github.jho951.ratelimiter.core.RateLimitKey;
import io.github.jho951.ratelimiter.core.RateLimitKeyType;
import io.github.jho951.ratelimiter.core.RateLimitPlan;
import io.github.jho951.ratelimiter.spi.RateLimiter;

import java.time.Duration;
import java.util.Objects;

/**
 * 고정 window quota를 적용하는 단순 rate limit policy다.
 *
 * <p>운영과 local/test 모두 호출자가 명시적으로 {@link RateLimiter}를 주입해야 한다.</p>
 */
final class FixedWindowRateLimitPolicy implements SecurityPolicy {
    private final int limit;
    private final Duration window;
    private final RateLimiter rateLimiter;

    FixedWindowRateLimitPolicy(int limit, Duration window, RateLimiter rateLimiter) {
        this.limit = limit;
        this.window = Objects.requireNonNull(window, "window");
        this.rateLimiter = Objects.requireNonNull(rateLimiter, "rateLimiter");
    }

    @Override
    public String name() {
        return "rate-limiter";
    }

    @Override
    public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
        if (limit <= 0) return SecurityVerdict.allow(name(), "rate limit disabled");

        String value = request.subject() != null ? request.subject() : request.clientIp();
        RateLimitKeyType keyType = request.subject() != null ? RateLimitKeyType.USER_ID : RateLimitKeyType.IP;
        String boundary = request.attributes().getOrDefault(SecurityAttributes.BOUNDARY, "UNKNOWN");
        RateLimitKey key = RateLimitKey.of(keyType, boundary + ":" + value);
        long windowSeconds = Math.max(1L, window.toSeconds());
        double refillPerSecond = (double) limit / (double) windowSeconds;
        RateLimitPlan plan = RateLimitPlan.perSecond(limit, refillPerSecond);
        RateLimitDecision decision = rateLimiter.tryAcquire(key, 1L, plan);
        if (!decision.isAllowed()) return SecurityVerdict.deny(name(), "rate limit exceeded for " + key.asString());
        return SecurityVerdict.allow(name(), "within rate limit");
    }
}
