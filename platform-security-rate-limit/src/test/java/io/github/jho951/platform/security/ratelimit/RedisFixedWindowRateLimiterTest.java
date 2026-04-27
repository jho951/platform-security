package io.github.jho951.platform.security.ratelimit;

import io.github.jho951.ratelimiter.core.RateLimitDecision;
import io.github.jho951.ratelimiter.core.RateLimitKey;
import io.github.jho951.ratelimiter.core.RateLimitKeyType;
import io.github.jho951.ratelimiter.core.RateLimitPlan;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.lang.reflect.Proxy;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RedisFixedWindowRateLimiterTest {

    @Test
    void allowsRequestsWithinWindowCapacity() {
        RecordingStringRedisTemplate redisTemplate = new RecordingStringRedisTemplate(1L);
        RedisFixedWindowRateLimiter limiter = new RedisFixedWindowRateLimiter(
                redisTemplate,
                "prefix:",
                Clock.fixed(Instant.ofEpochSecond(20L), ZoneOffset.UTC)
        );

        RateLimitDecision decision = limiter.tryAcquire(
                RateLimitKey.of(RateLimitKeyType.USER_ID, "user-1"),
                1L,
                RateLimitPlan.perSecond(10L, 1.0d)
        );

        assertTrue(decision.isAllowed());
        assertEquals(9L, decision.getRemainingTokens());
        assertEquals("prefix:user:user-1:2", redisTemplate.expiredKey);
        assertEquals(Duration.ofSeconds(11L), redisTemplate.expireDuration);
    }

    @Test
    void deniesRequestsOverWindowCapacityWithRetryAfter() {
        RecordingStringRedisTemplate redisTemplate = new RecordingStringRedisTemplate(11L);
        RedisFixedWindowRateLimiter limiter = new RedisFixedWindowRateLimiter(
                redisTemplate,
                "prefix:",
                Clock.fixed(Instant.ofEpochSecond(20L), ZoneOffset.UTC)
        );

        RateLimitDecision decision = limiter.tryAcquire(
                RateLimitKey.of(RateLimitKeyType.IP, "127.0.0.1"),
                1L,
                RateLimitPlan.perSecond(10L, 1.0d)
        );

        assertFalse(decision.isAllowed());
        assertEquals(10000L, decision.getRetryAfterMillis());
    }

    private static final class RecordingStringRedisTemplate extends StringRedisTemplate {
        private final ValueOperations<String, String> valueOperations;
        private String expiredKey;
        private Duration expireDuration;

        @SuppressWarnings("unchecked")
        private RecordingStringRedisTemplate(long incrementResult) {
            this.valueOperations = (ValueOperations<String, String>) Proxy.newProxyInstance(
                    ValueOperations.class.getClassLoader(),
                    new Class<?>[]{ValueOperations.class},
                    (proxy, method, args) -> {
                        if (method.getName().equals("increment")) {
                            return incrementResult;
                        }
                        if (method.getDeclaringClass() == Object.class) {
                            return method.invoke(this, args);
                        }
                        return null;
                    }
            );
        }

        @Override
        public ValueOperations<String, String> opsForValue() {
            return valueOperations;
        }

        @Override
        public Boolean expire(String key, Duration timeout) {
            this.expiredKey = key;
            this.expireDuration = timeout;
            return Boolean.TRUE;
        }
    }
}
