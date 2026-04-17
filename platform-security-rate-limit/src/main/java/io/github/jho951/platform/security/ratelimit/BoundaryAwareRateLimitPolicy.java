package io.github.jho951.platform.security.ratelimit;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.api.ResolvedSecurityProfile;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.RateLimitKeyResolver;
import io.github.jho951.platform.security.policy.SecurityAttributes;
import io.github.jho951.platform.security.policy.SecurityBoundary;
import io.github.jho951.platform.security.policy.SecurityBoundaryType;
import io.github.jho951.ratelimiter.core.RateLimitDecision;
import io.github.jho951.ratelimiter.core.RateLimitKey;
import io.github.jho951.ratelimiter.core.RateLimitKeyType;
import io.github.jho951.ratelimiter.core.RateLimitPlan;
import io.github.jho951.ratelimiter.spi.RateLimiter;

import java.util.Objects;

/**
 * boundary, client type, auth mode, route pattern에 맞는 quota를 선택해 평가하는 rate limit policy다.
 */
public final class BoundaryAwareRateLimitPolicy implements SecurityPolicy {
    private final SecurityBoundary boundary;
    private final PlatformSecurityProperties.RateLimitProperties properties;
    private final RateLimitKeyResolver keyResolver;
    private final RateLimiter rateLimiter;

    public BoundaryAwareRateLimitPolicy(
            SecurityBoundary boundary,
            PlatformSecurityProperties.RateLimitProperties properties,
            RateLimitKeyResolver keyResolver,
            RateLimiter rateLimiter
    ) {
        this.boundary = Objects.requireNonNull(boundary, "boundary");
        this.properties = properties == null ? new PlatformSecurityProperties.RateLimitProperties() : properties;
        this.keyResolver = Objects.requireNonNull(keyResolver, "keyResolver");
        this.rateLimiter = Objects.requireNonNull(rateLimiter, "rateLimiter");
    }

    @Override
    public String name() {
        return "rate-limiter";
    }

    @Override
    public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(context, "context");
        if (!properties.isEnabled()) {
            return SecurityVerdict.allow(name(), "rate limit disabled");
        }

        PlatformSecurityProperties.BoundaryRateLimitPolicyProperties profile = selectProfile(request, context);
        if (profile == null || profile.getRequests() <= 0L) {
            return SecurityVerdict.allow(name(), "rate limit disabled");
        }

        ResolvedSecurityProfile resolvedProfile = new ResolvedSecurityProfile(
                boundary.type().name(),
                boundary.patterns(),
                trimToUpper(request.attributes().getOrDefault(SecurityAttributes.CLIENT_TYPE, "EXTERNAL_API")),
                trimToUpper(request.attributes().getOrDefault(SecurityAttributes.AUTH_MODE, context.authenticated() ? "HYBRID" : "NONE"))
        );
        String keyValue = keyResolver.resolve(request, context, resolvedProfile);
        RateLimitKeyType keyType = context.authenticated() ? RateLimitKeyType.USER_ID : RateLimitKeyType.IP;
        RateLimitKey key = RateLimitKey.of(keyType, keyValue);
        long windowSeconds = Math.max(1L, profile.getWindowSeconds());
        int limit = Math.toIntExact(profile.getRequests());
        double refillPerSecond = (double) limit / (double) windowSeconds;
        RateLimitPlan plan = RateLimitPlan.perSecond(limit, refillPerSecond);
        RateLimitDecision decision = rateLimiter.tryAcquire(key, 1L, plan);
        if (!decision.isAllowed()) {
            return SecurityVerdict.deny(name(), "rate limit exceeded for " + key.asString());
        }
        return SecurityVerdict.allow(name(), "within rate limit");
    }

    private PlatformSecurityProperties.BoundaryRateLimitPolicyProperties selectProfile(SecurityRequest request, SecurityContext context) {
        PlatformSecurityProperties.RouteRateLimitPolicyProperties routeProfile = selectRouteProfile(request.path());
        if (routeProfile != null) {
            return routeProfile;
        }
        if (boundary.type() == SecurityBoundaryType.PUBLIC) {
            return null;
        }
        String clientType = trimToUpper(request.attributes().get(SecurityAttributes.CLIENT_TYPE));
        String authMode = trimToUpper(request.attributes().get(SecurityAttributes.AUTH_MODE));
        if (boundary.type() == SecurityBoundaryType.INTERNAL || "INTERNAL_SERVICE".equals(clientType)) {
            return properties.getInternal();
        }
        if ("NONE".equals(authMode) || !context.authenticated()) {
            return properties.getAnonymous();
        }
        if ("BROWSER".equals(clientType) || "SESSION".equals(authMode) || "HYBRID".equals(authMode) || "JWT".equals(authMode)) {
            return properties.getAuthenticated();
        }
        return context.authenticated() ? properties.getAuthenticated() : properties.getAnonymous();
    }

    private PlatformSecurityProperties.RouteRateLimitPolicyProperties selectRouteProfile(String path) {
        if (path == null || properties.getRoutes().isEmpty()) {
            return null;
        }
        for (PlatformSecurityProperties.RouteRateLimitPolicyProperties route : properties.getRoutes()) {
            if (route == null || route.getPatterns().isEmpty()) {
                continue;
            }
            for (String pattern : route.getPatterns()) {
                if (matchesPattern(path, pattern)) {
                    return route;
                }
            }
        }
        return null;
    }

    private boolean matchesPattern(String path, String pattern) {
        if (pattern == null || pattern.isBlank()) {
            return false;
        }
        String normalizedPath = path.startsWith("/") ? path : "/" + path;
        String normalizedPattern = pattern.trim();
        if (normalizedPattern.endsWith("/**")) {
            String prefix = normalizedPattern.substring(0, normalizedPattern.length() - 3);
            return normalizedPath.startsWith(prefix);
        }
        return normalizedPath.equals(normalizedPattern) || normalizedPath.startsWith(normalizedPattern + "/");
    }

    private String trimToUpper(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed.toUpperCase(java.util.Locale.ROOT);
    }
}
