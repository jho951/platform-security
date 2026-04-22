package io.github.jho951.platform.security.ratelimit;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.policy.SecurityAttributes;

import java.time.Duration;
import java.util.Objects;

/**
 * 고정 window quota를 적용하는 단순 rate limit policy다.
 */
final class FixedWindowRateLimitPolicy implements SecurityPolicy {
    private final int limit;
    private final Duration window;
    private final PlatformRateLimitPort rateLimitPort;

    FixedWindowRateLimitPolicy(int limit, Duration window, PlatformRateLimitPort rateLimitPort) {
        this.limit = limit;
        this.window = Objects.requireNonNull(window, "window");
        this.rateLimitPort = Objects.requireNonNull(rateLimitPort, "rateLimitPort");
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
        String boundary = request.attributes().getOrDefault(SecurityAttributes.BOUNDARY, "UNKNOWN");
        String key = boundary + ":" + value;
        PlatformRateLimitDecision decision = rateLimitPort.evaluate(new PlatformRateLimitRequest(
                key,
                request.subject() != null ? PlatformRateLimitKeyType.USER : PlatformRateLimitKeyType.IP,
                1L,
                limit,
                Math.max(1L, window.toSeconds())
        ));
        if (!decision.allowed()) {
            return SecurityVerdict.deny(name(), "rate limit exceeded for " + key);
        }
        return SecurityVerdict.allow(name(), "within rate limit");
    }
}
