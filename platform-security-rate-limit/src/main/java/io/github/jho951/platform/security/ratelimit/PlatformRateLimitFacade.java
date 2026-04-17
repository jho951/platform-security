package io.github.jho951.platform.security.ratelimit;

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
 * 독립 실행 코드에서 rate limit policy를 직접 호출하기 위한 작은 facade다.
 */
public final class PlatformRateLimitFacade {
    private final SecurityPolicy policy;

    public PlatformRateLimitFacade(int limit, Duration window, RateLimiter rateLimiter) {
        this.policy = new FixedWindowPolicy(limit, window, rateLimiter);
    }

    public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
        return policy.evaluate(request, context);
    }

    public SecurityPolicy policy() {
        return policy;
    }

    private static final class FixedWindowPolicy implements SecurityPolicy {
        private final int limit;
        private final Duration window;
        private final RateLimiter rateLimiter;

        private FixedWindowPolicy(int limit, Duration window, RateLimiter rateLimiter) {
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
            if (limit <= 0) {
                return SecurityVerdict.allow(name(), "rate limit disabled");
            }

            String value = request.subject() != null ? request.subject() : request.clientIp();
            RateLimitKeyType keyType = request.subject() != null ? RateLimitKeyType.USER_ID : RateLimitKeyType.IP;
            String boundary = request.attributes().getOrDefault(SecurityAttributes.BOUNDARY, "UNKNOWN");
            RateLimitKey key = RateLimitKey.of(keyType, boundary + ":" + value);
            long windowSeconds = Math.max(1L, window.toSeconds());
            double refillPerSecond = (double) limit / (double) windowSeconds;
            RateLimitPlan plan = RateLimitPlan.perSecond(limit, refillPerSecond);
            RateLimitDecision decision = rateLimiter.tryAcquire(key, 1L, plan);
            if (!decision.isAllowed()) {
                return SecurityVerdict.deny(name(), "rate limit exceeded for " + key.asString());
            }
            return SecurityVerdict.allow(name(), "within rate limit");
        }
    }
}
