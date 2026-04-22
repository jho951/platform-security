package io.github.jho951.platform.security.ratelimit;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityDecision;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class FixedWindowRateLimitPolicyTest {
    @Test
    void deniesWhenLimitExceeded() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        FixedWindowRateLimitPolicy policy = new FixedWindowRateLimitPolicy(
                1,
                Duration.ofMinutes(1),
                new DefaultPlatformRateLimitAdapter(new InMemoryRateLimiter(clock))
        );

        SecurityRequest request = new SecurityRequest("user-1", "127.0.0.1", "/api", "read", Map.of(), clock.instant());
        SecurityContext context = new SecurityContext(true, "user-1", Set.of("USER"), Map.of());

        SecurityVerdict first = policy.evaluate(request, context);
        SecurityVerdict second = policy.evaluate(request, context);

        assertEquals(SecurityDecision.ALLOW, first.decision());
        assertEquals(SecurityDecision.DENY, second.decision());
    }

    private static final class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }

        @Override
        public long millis() {
            return instant.toEpochMilli();
        }
    }
}
