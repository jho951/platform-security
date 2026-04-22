package io.github.jho951.platform.security.ratelimit;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.policy.SecurityAttributes;

import java.time.Duration;
import java.util.Objects;

/**
 * 독립 실행 코드에서 rate limit policy를 직접 호출하기 위한 작은 facade다.
 */
public final class PlatformRateLimitFacade {
    private final SecurityPolicy policy;

    public PlatformRateLimitFacade(int limit, Duration window, PlatformRateLimitAdapter rateLimitAdapter) {
        this.policy = new FixedWindowPolicy(limit, window, rateLimitAdapter);
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
        private final PlatformRateLimitAdapter rateLimitAdapter;

        private FixedWindowPolicy(int limit, Duration window, PlatformRateLimitAdapter rateLimitAdapter) {
            this.limit = limit;
            this.window = Objects.requireNonNull(window, "window");
            this.rateLimitAdapter = Objects.requireNonNull(rateLimitAdapter, "rateLimitAdapter");
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
            PlatformRateLimitDecision decision = rateLimitAdapter.evaluate(new PlatformRateLimitRequest(
                    boundary + ":" + value,
                    request.subject() != null ? PlatformRateLimitKeyType.USER : PlatformRateLimitKeyType.IP,
                    1L,
                    limit,
                    Math.max(1L, window.toSeconds())
            ));
            if (!decision.allowed()) {
                return SecurityVerdict.deny(name(), decision.detail());
            }
            return SecurityVerdict.allow(name(), decision.detail());
        }
    }
}
