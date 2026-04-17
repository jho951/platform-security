package io.github.jho951.platform.security.ratelimit;

import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.ResolvedSecurityProfile;
import io.github.jho951.platform.security.policy.BoundaryRateLimitPolicyProvider;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.RateLimitKeyResolver;
import io.github.jho951.platform.security.policy.SecurityBoundary;
import io.github.jho951.platform.security.core.policy.FixedWindowRateLimitPolicy;

import io.github.jho951.platform.security.core.limiter.InMemoryRateLimiter;
import io.github.jho951.ratelimiter.spi.RateLimiter;

import java.time.Clock;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * boundary/profile 조합별 {@link BoundaryAwareRateLimitPolicy}를 생성하고 재사용하는 provider다.
 */
public final class DefaultBoundaryRateLimitPolicyProvider implements BoundaryRateLimitPolicyProvider {
    private final PlatformSecurityProperties.RateLimitProperties properties;
    private final RateLimitKeyResolver keyResolver;
    private final RateLimiter rateLimiter;
    private final Map<String, SecurityPolicy> cache = new ConcurrentHashMap<>();

    public DefaultBoundaryRateLimitPolicyProvider(
            PlatformSecurityProperties.RateLimitProperties properties,
            RateLimitKeyResolver keyResolver
    ) {
        this(properties, keyResolver, new InMemoryRateLimiter(Clock.systemUTC()));
    }

    public DefaultBoundaryRateLimitPolicyProvider(
            PlatformSecurityProperties.RateLimitProperties properties,
            RateLimitKeyResolver keyResolver,
            RateLimiter rateLimiter
    ) {
        this.properties = properties == null ? new PlatformSecurityProperties.RateLimitProperties() : properties;
        this.keyResolver = Objects.requireNonNull(keyResolver, "keyResolver");
        this.rateLimiter = Objects.requireNonNull(rateLimiter, "rateLimiter");
    }

    @Override
    public synchronized SecurityPolicy resolve(SecurityBoundary boundary) {
        return resolve(boundary, null);
    }

    @Override
    public synchronized SecurityPolicy resolve(SecurityBoundary boundary, ResolvedSecurityProfile profile) {
        Objects.requireNonNull(boundary, "boundary");
        if (!properties.isEnabled()) {
            return new FixedWindowRateLimitPolicy(0, java.time.Duration.ofSeconds(1));
        }
        String cacheKey = cacheKey(boundary, profile);
        return cache.computeIfAbsent(cacheKey, type -> new BoundaryAwareRateLimitPolicy(
                boundary,
                properties,
                keyResolver,
                rateLimiter
        ));
    }

    private String cacheKey(SecurityBoundary boundary, ResolvedSecurityProfile profile) {
        if (profile == null) {
            return boundary.type().name() + ":default";
        }
        return boundary.type().name()
                + ":"
                + profile.boundaryType()
                + ":"
                + profile.clientType()
                + ":"
                + profile.authMode();
    }
}
