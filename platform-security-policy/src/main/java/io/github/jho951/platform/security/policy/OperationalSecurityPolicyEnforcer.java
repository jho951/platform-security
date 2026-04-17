package io.github.jho951.platform.security.policy;

import io.github.jho951.platform.policy.api.OperationalProfileResolver;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * 운영 profile에서 local/test fallback이나 느슨한 보안 설정을 fail-fast로 차단한다.
 *
 * <p>현재 기본 운영 profile은 {@code prod}이며, 설정으로 강제 production mode를 켤 수
 * 있다. 이 enforcer는 Spring auto-configuration의 부팅 guard에서 호출된다.</p>
 */
public final class OperationalSecurityPolicyEnforcer {
    private final OperationalProfileResolver operationalProfileResolver;

    public OperationalSecurityPolicyEnforcer() {
        this(OperationalProfileResolver.standard());
    }

    public OperationalSecurityPolicyEnforcer(OperationalProfileResolver operationalProfileResolver) {
        this.operationalProfileResolver = Objects.requireNonNull(operationalProfileResolver, "operationalProfileResolver");
    }

    public void enforce(
            PlatformSecurityProperties properties,
            boolean securityContextResolverPresent,
            boolean platformDefaultTokenServicePresent,
            String... activeProfiles
    ) {
        enforce(
                properties,
                securityContextResolverPresent,
                platformDefaultTokenServicePresent,
                false,
                true,
                platformDefaultTokenServicePresent,
                false,
                false,
                false,
                activeProfiles
        );
    }

    public void enforce(
            PlatformSecurityProperties properties,
            boolean securityContextResolverPresent,
            boolean platformDefaultTokenServicePresent,
            boolean platformDefaultRateLimiterPresent,
            String... activeProfiles
    ) {
        enforce(
                properties,
                securityContextResolverPresent,
                platformDefaultTokenServicePresent,
                false,
                true,
                platformDefaultTokenServicePresent,
                false,
                platformDefaultRateLimiterPresent,
                false,
                activeProfiles
        );
    }

    public void enforce(
            PlatformSecurityProperties properties,
            boolean securityContextResolverPresent,
            boolean platformDefaultTokenServicePresent,
            boolean platformDefaultSessionStorePresent,
            boolean rateLimiterPresent,
            boolean inMemoryRateLimiterPresent,
            boolean platformDefaultInternalTokenClaimsValidatorPresent,
            String... activeProfiles
    ) {
        enforce(
                properties,
                securityContextResolverPresent,
                platformDefaultTokenServicePresent,
                platformDefaultSessionStorePresent,
                rateLimiterPresent,
                platformDefaultTokenServicePresent,
                platformDefaultSessionStorePresent,
                inMemoryRateLimiterPresent,
                platformDefaultInternalTokenClaimsValidatorPresent,
                activeProfiles
        );
    }

    public void enforce(
            PlatformSecurityProperties properties,
            boolean securityContextResolverPresent,
            boolean platformDefaultTokenServicePresent,
            boolean platformDefaultSessionStorePresent,
            boolean rateLimiterPresent,
            boolean tokenServicePresent,
            boolean sessionStorePresent,
            boolean inMemoryRateLimiterPresent,
            boolean platformDefaultInternalTokenClaimsValidatorPresent,
            String... activeProfiles
    ) {
        Objects.requireNonNull(properties, "properties");
        if (!properties.isEnabled() || !properties.getOperationalPolicy().isEnabled()) {
            return;
        }
        if (!isProduction(properties, activeProfiles)) {
            return;
        }

        List<String> violations = new ArrayList<>();
        validateAuth(
                properties,
                securityContextResolverPresent,
                platformDefaultTokenServicePresent,
                platformDefaultSessionStorePresent,
                platformDefaultInternalTokenClaimsValidatorPresent,
                violations
        );
        validateIssuer(properties, tokenServicePresent, sessionStorePresent, violations);
        validateIpGuard(properties, violations);
        validateRateLimit(properties, rateLimiterPresent, inMemoryRateLimiterPresent, violations);
        if (!violations.isEmpty()) {
            throw new IllegalStateException("Platform security operational policy violation: " + String.join("; ", violations));
        }
    }

    private void validateIssuer(
            PlatformSecurityProperties properties,
            boolean tokenServicePresent,
            boolean sessionStorePresent,
            List<String> violations
    ) {
        if (properties.getServiceRolePreset() != ServiceRolePreset.ISSUER) {
            return;
        }
        if (!tokenServicePresent) {
            violations.add("issuer services must provide a production TokenService bean");
        }
        if (properties.getAuth().isAllowSessionForBrowser() && !sessionStorePresent) {
            violations.add("issuer services with browser session support must provide a production SessionStore bean");
        }
    }

    private boolean isProduction(PlatformSecurityProperties properties, String... activeProfiles) {
        if (properties.getOperationalPolicy().isProduction()) {
            return true;
        }
        return operationalProfileResolver.isProduction(
                Arrays.asList(activeProfiles == null ? new String[0] : activeProfiles),
                properties.getOperationalPolicy().getProductionProfiles()
        );
    }

    private void validateAuth(
            PlatformSecurityProperties properties,
            boolean securityContextResolverPresent,
            boolean platformDefaultTokenServicePresent,
            boolean platformDefaultSessionStorePresent,
            boolean platformDefaultInternalTokenClaimsValidatorPresent,
            List<String> violations
    ) {
        PlatformSecurityProperties.AuthProperties auth = properties.getAuth();
        if (!auth.isEnabled()) {
            violations.add("platform.security.auth.enabled must be true in production");
            return;
        }
        if (auth.getDefaultMode() == AuthMode.NONE) {
            violations.add("platform.security.auth.default-mode must not be NONE in production");
        }
        if (auth.getDevFallback().isEnabled()) {
            violations.add("platform.security.auth.dev-fallback.enabled must be false in production");
        }
        if (!securityContextResolverPresent) {
            violations.add("production SecurityContextResolver bean is required");
        }
        if (platformDefaultTokenServicePresent) {
            violations.add("production TokenService bean must be provided; platform JwtTokenService is local/test only");
        }
        if (PlatformSecurityProperties.DEFAULT_JWT_SECRET.equals(auth.getJwtSecret())) {
            violations.add("platform.security.auth.jwt-secret must not use the platform dev default in production");
        }
        if (platformDefaultSessionStorePresent) {
            violations.add("production SessionStore bean must be provided; platform SimpleSessionStore is local/test only");
        }
        if (auth.isInternalTokenEnabled() && platformDefaultInternalTokenClaimsValidatorPresent) {
            violations.add("production InternalTokenClaimsValidator bean must be provided; platform local validator is local/test only");
        }
    }

    private void validateIpGuard(PlatformSecurityProperties properties, List<String> violations) {
        PlatformSecurityProperties.IpGuardProperties ipGuard = properties.getIpGuard();
        if (!ipGuard.isEnabled()) {
            violations.add("platform.security.ip-guard.enabled must be true in production");
        }
        if (ipGuard.isTrustProxy() && ipGuard.getTrustedProxyCidrs().isEmpty()) {
            violations.add("platform.security.ip-guard.trusted-proxy-cidrs must not be empty when trust-proxy=true in production");
        }
        validateIpRulePolicy("platform.security.ip-guard.admin", ipGuard.getAdmin(), violations);
        validateIpRulePolicy("platform.security.ip-guard.internal", ipGuard.getInternal(), violations);
    }

    private void validateRateLimit(
            PlatformSecurityProperties properties,
            boolean rateLimiterPresent,
            boolean inMemoryRateLimiterPresent,
            List<String> violations
    ) {
        PlatformSecurityProperties.RateLimitProperties rateLimit = properties.getRateLimit();
        if (!rateLimit.isEnabled()) {
            violations.add("platform.security.rate-limit.enabled must be true in production");
            return;
        }
        if (!rateLimiterPresent) {
            violations.add("production RateLimiter bean is required");
        }
        if (inMemoryRateLimiterPresent) {
            violations.add("production RateLimiter bean must be distributed; in-memory rate limiter is local/test only");
        }
        validateQuota("platform.security.rate-limit.anonymous", rateLimit.getAnonymous(), violations);
        validateQuota("platform.security.rate-limit.authenticated", rateLimit.getAuthenticated(), violations);
        validateQuota("platform.security.rate-limit.internal", rateLimit.getInternal(), violations);
        for (int i = 0; i < rateLimit.getRoutes().size(); i++) {
            PlatformSecurityProperties.RouteRateLimitPolicyProperties route = rateLimit.getRoutes().get(i);
            validateQuota("platform.security.rate-limit.routes[" + i + "]", route, violations);
            if (route.getPatterns().isEmpty()) {
                violations.add("platform.security.rate-limit.routes[" + i + "].patterns must not be empty in production");
            }
        }
    }

    private void validateQuota(
            String prefix,
            PlatformSecurityProperties.BoundaryRateLimitPolicyProperties quota,
            List<String> violations
    ) {
        if (quota.getRequests() <= 0L) {
            violations.add(prefix + ".requests must be greater than 0 in production");
        }
        if (quota.getWindowSeconds() <= 0L) {
            violations.add(prefix + ".window-seconds must be greater than 0 in production");
        }
    }

    private void validateIpRulePolicy(
            String prefix,
            PlatformSecurityProperties.BoundaryIpGuardPolicy policy,
            List<String> violations
    ) {
        PlatformSecurityProperties.BoundaryIpGuardPolicy effective =
                policy == null ? new PlatformSecurityProperties.BoundaryIpGuardPolicy() : policy;
        if (effective.isDefaultAllow()) {
            violations.add(prefix + ".default-allow must be false in production");
        }
        switch (effective.getSource()) {
            case INLINE -> {
                if (effective.getRules().isEmpty()) {
                    violations.add(prefix + ".rules must not be empty when source=INLINE in production");
                }
            }
            case FILE -> {
                if (effective.getLocation() == null || effective.getLocation().isBlank()) {
                    violations.add(prefix + ".location must not be empty when source=FILE in production");
                }
                validateDynamicSourceReloadTtl(prefix, effective, violations);
            }
            case POLICY_CONFIG -> {
                if (effective.getPolicyKey() == null || effective.getPolicyKey().isBlank()) {
                    violations.add(prefix + ".policy-key must not be empty when source=POLICY_CONFIG in production");
                }
                validateDynamicSourceReloadTtl(prefix, effective, violations);
            }
        }
    }

    private void validateDynamicSourceReloadTtl(
            String prefix,
            PlatformSecurityProperties.BoundaryIpGuardPolicy policy,
            List<String> violations
    ) {
        if (policy.getReloadTtl() == null || policy.getReloadTtl().isZero() || policy.getReloadTtl().isNegative()) {
            violations.add(prefix + ".reload-ttl must be greater than 0 for dynamic IP rule sources in production");
        }
    }
}
