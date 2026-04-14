package io.github.jho951.platform.security.policy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public final class OperationalSecurityPolicyEnforcer {
    public void enforce(
            PlatformSecurityProperties properties,
            boolean securityContextResolverPresent,
            boolean platformDefaultTokenServicePresent,
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
        validateAuth(properties, securityContextResolverPresent, platformDefaultTokenServicePresent, violations);
        validateIpGuard(properties, violations);
        validateRateLimit(properties, violations);
        if (!violations.isEmpty()) {
            throw new IllegalStateException("Platform security operational policy violation: " + String.join("; ", violations));
        }
    }

    private boolean isProduction(PlatformSecurityProperties properties, String... activeProfiles) {
        if (properties.getOperationalPolicy().isProduction()) {
            return true;
        }
        return Arrays.stream(activeProfiles == null ? new String[0] : activeProfiles)
                .anyMatch(properties.getOperationalPolicy()::isProductionProfile);
    }

    private void validateAuth(
            PlatformSecurityProperties properties,
            boolean securityContextResolverPresent,
            boolean platformDefaultTokenServicePresent,
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
        if (platformDefaultTokenServicePresent && PlatformSecurityProperties.DEFAULT_JWT_SECRET.equals(auth.getJwtSecret())) {
            violations.add("platform.security.auth.jwt-secret must not use the platform dev default in production");
        }
    }

    private void validateIpGuard(PlatformSecurityProperties properties, List<String> violations) {
        PlatformSecurityProperties.IpGuardProperties ipGuard = properties.getIpGuard();
        if (!ipGuard.isEnabled()) {
            violations.add("platform.security.ip-guard.enabled must be true in production");
        }
        if (ipGuard.getAdminAllowCidrs().isEmpty()) {
            violations.add("platform.security.ip-guard.admin-allow-cidrs must not be empty in production");
        }
        if (ipGuard.getInternalAllowCidrs().isEmpty()) {
            violations.add("platform.security.ip-guard.internal-allow-cidrs must not be empty in production");
        }
    }

    private void validateRateLimit(PlatformSecurityProperties properties, List<String> violations) {
        PlatformSecurityProperties.RateLimitProperties rateLimit = properties.getRateLimit();
        if (!rateLimit.isEnabled()) {
            violations.add("platform.security.rate-limit.enabled must be true in production");
            return;
        }
        validateQuota("platform.security.rate-limit.anonymous", rateLimit.getAnonymous(), violations);
        validateQuota("platform.security.rate-limit.authenticated", rateLimit.getAuthenticated(), violations);
        validateQuota("platform.security.rate-limit.internal", rateLimit.getInternal(), violations);
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
}
