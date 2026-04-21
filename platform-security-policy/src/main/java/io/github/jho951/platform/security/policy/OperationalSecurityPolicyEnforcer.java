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
            boolean platformDefaultTokenIssuerPortPresent,
            String... activeProfiles
    ) {
        enforce(
                properties,
                securityContextResolverPresent,
                platformDefaultTokenIssuerPortPresent,
                false,
                false,
                false,
                false,
                false,
                false,
                activeProfiles
        );
    }

    public void enforce(
            PlatformSecurityProperties properties,
            boolean securityContextResolverPresent,
            boolean platformDefaultTokenIssuerPortPresent,
            boolean platformDefaultRateLimitAdapterPresent,
            String... activeProfiles
    ) {
        enforce(
                properties,
                securityContextResolverPresent,
                platformDefaultTokenIssuerPortPresent,
                false,
                false,
                false,
                false,
                platformDefaultRateLimitAdapterPresent,
                false,
                activeProfiles
        );
    }

    public void enforce(
            PlatformSecurityProperties properties,
            boolean securityContextResolverPresent,
            boolean platformDefaultTokenIssuerPortPresent,
            boolean platformDefaultSessionIssuerPortPresent,
            boolean rateLimitAdapterPresent,
            boolean nonDistributedRateLimitAdapterPresent,
            boolean platformDefaultInternalTokenClaimsValidatorPresent,
            String... activeProfiles
    ) {
        enforce(
                properties,
                securityContextResolverPresent,
                platformDefaultTokenIssuerPortPresent,
                platformDefaultSessionIssuerPortPresent,
                rateLimitAdapterPresent,
                false,
                false,
                nonDistributedRateLimitAdapterPresent,
                platformDefaultInternalTokenClaimsValidatorPresent,
                activeProfiles
        );
    }

    public void enforce(
            PlatformSecurityProperties properties,
            boolean securityContextResolverPresent,
            boolean platformDefaultTokenIssuerPortPresent,
            boolean platformDefaultSessionIssuerPortPresent,
            boolean rateLimitAdapterPresent,
            boolean tokenIssuerPortPresent,
            boolean sessionIssuerPortPresent,
            boolean nonDistributedRateLimitAdapterPresent,
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
                platformDefaultTokenIssuerPortPresent,
                platformDefaultSessionIssuerPortPresent,
                platformDefaultInternalTokenClaimsValidatorPresent,
                violations
        );
        validateIssuer(properties, tokenIssuerPortPresent, sessionIssuerPortPresent, violations);
        validateIpGuard(properties, violations);
        validateRateLimit(properties, rateLimitAdapterPresent, nonDistributedRateLimitAdapterPresent, violations);
        if (!violations.isEmpty()) {
            throw new IllegalStateException("Platform security operational policy violation: " + String.join("; ", violations));
        }
    }

    private void validateIssuer(
            PlatformSecurityProperties properties,
            boolean tokenIssuerPortPresent,
            boolean sessionIssuerPortPresent,
            List<String> violations
    ) {
        if (properties.getServiceRolePreset() != ServiceRolePreset.ISSUER) {
            return;
        }
        if (!tokenIssuerPortPresent) {
            violations.add("issuer services must provide a production PlatformTokenIssuerPort bean");
        }
        if (properties.getAuth().isAllowSessionForBrowser() && !sessionIssuerPortPresent) {
            violations.add("issuer services with browser session support must provide a production PlatformSessionIssuerPort bean");
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
            boolean platformDefaultTokenIssuerPortPresent,
            boolean platformDefaultSessionIssuerPortPresent,
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
        if (platformDefaultTokenIssuerPortPresent) {
            violations.add("production PlatformTokenIssuerPort bean must be provided; platform local issuer port is local/test only");
        }
        if (PlatformSecurityProperties.DEFAULT_JWT_SECRET.equals(auth.getJwtSecret())) {
            violations.add("platform.security.auth.jwt-secret must not use the platform dev default in production");
        }
        if (platformDefaultSessionIssuerPortPresent) {
            violations.add("production PlatformSessionIssuerPort bean must be provided; platform local session issuer port is local/test only");
        }
        if (auth.isInternalTokenEnabled() && platformDefaultInternalTokenClaimsValidatorPresent) {
            violations.add("production InternalTokenClaimsValidator bean must be provided; platform local validator is local/test only");
        }
    }

    private void validateIpGuard(PlatformSecurityProperties properties, List<String> violations) {
        PlatformSecurityProperties.IpGuardProperties ipGuard = properties.getIpGuard();
        if (!ipGuard.isEnabled()) {
            if (requiresStrictIngressControls(properties.getServiceRolePreset())
                    && !properties.getOperationalPolicy().isAllowIpGuardDisabledInProduction()) {
                violations.add("platform.security.ip-guard.enabled must be true in production for preset "
                        + properties.getServiceRolePreset().name());
            }
            return;
        }
        if (ipGuard.isTrustProxy() && ipGuard.getTrustedProxyCidrs().isEmpty()) {
            violations.add("platform.security.ip-guard.trusted-proxy-cidrs must not be empty when trust-proxy=true in production");
        }
        validateIpRulePolicy("platform.security.ip-guard.admin", ipGuard.getAdmin(), violations);
        validateIpRulePolicy("platform.security.ip-guard.internal", ipGuard.getInternal(), violations);
    }

    private void validateRateLimit(
            PlatformSecurityProperties properties,
            boolean rateLimitAdapterPresent,
            boolean nonDistributedRateLimitAdapterPresent,
            List<String> violations
    ) {
        PlatformSecurityProperties.RateLimitProperties rateLimit = properties.getRateLimit();
        if (!rateLimit.isEnabled()) {
            if (requiresStrictIngressControls(properties.getServiceRolePreset())
                    && !properties.getOperationalPolicy().isAllowRateLimitDisabledInProduction()) {
                violations.add("platform.security.rate-limit.enabled must be true in production for preset "
                        + properties.getServiceRolePreset().name());
            }
            return;
        }
        if (!rateLimitAdapterPresent) {
            violations.add("production PlatformRateLimitAdapter bean is required");
        }
        if (requiresStrictIngressControls(properties.getServiceRolePreset())
                && nonDistributedRateLimitAdapterPresent
                && !properties.getOperationalPolicy().isAllowNonDistributedRateLimiterInProduction()) {
            violations.add("production PlatformRateLimitAdapter bean must be distributed; platform local rate limiter is local/test only");
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

    private boolean requiresStrictIngressControls(ServiceRolePreset preset) {
        if (preset == null) {
            return true;
        }
        return switch (preset) {
            case EDGE, API_SERVER, GENERAL -> true;
            case INTERNAL_SERVICE, ISSUER -> false;
        };
    }
}
