package io.github.jho951.platform.security.ratelimit;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.core.policy.FixedWindowRateLimitPolicy;

import java.time.Duration;
import java.util.Objects;

public final class PlatformRateLimitFacade {
    private final FixedWindowRateLimitPolicy policy;

    public PlatformRateLimitFacade(int limit, Duration window) {
        this.policy = new FixedWindowRateLimitPolicy(limit, window);
    }

    public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
        return policy.evaluate(request, context);
    }

    public FixedWindowRateLimitPolicy policy() {
        return policy;
    }
}
