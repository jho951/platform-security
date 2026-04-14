package io.github.jho951.platform.security.policy;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public class PlatformSecurityProperties {
    public static final String DEFAULT_JWT_SECRET = "platform-security-dev-secret-platform-security-dev-secret";

    private boolean enabled = true;
    private ServiceRolePreset serviceRolePreset = ServiceRolePreset.GENERAL;
    private OperationalPolicyProperties operationalPolicy = new OperationalPolicyProperties();
    private BoundaryPolicyProperties boundary = new BoundaryPolicyProperties();
    private AuthProperties auth = new AuthProperties();
    private IpGuardProperties ipGuard = new IpGuardProperties();
    private RateLimitProperties rateLimit = new RateLimitProperties();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public ServiceRolePreset getServiceRolePreset() {
        return serviceRolePreset;
    }

    public void setServiceRolePreset(ServiceRolePreset serviceRolePreset) {
        this.serviceRolePreset = serviceRolePreset == null ? ServiceRolePreset.GENERAL : serviceRolePreset;
    }

    public OperationalPolicyProperties getOperationalPolicy() {
        return operationalPolicy;
    }

    public void setOperationalPolicy(OperationalPolicyProperties operationalPolicy) {
        this.operationalPolicy = operationalPolicy == null ? new OperationalPolicyProperties() : operationalPolicy;
    }

    public BoundaryPolicyProperties getBoundary() {
        return boundary;
    }

    public void setBoundary(BoundaryPolicyProperties boundary) {
        this.boundary = boundary == null ? new BoundaryPolicyProperties() : boundary;
    }

    public AuthProperties getAuth() {
        return auth;
    }

    public void setAuth(AuthProperties auth) {
        this.auth = auth == null ? new AuthProperties() : auth;
    }

    public IpGuardProperties getIpGuard() {
        return ipGuard;
    }

    public void setIpGuard(IpGuardProperties ipGuard) {
        this.ipGuard = ipGuard == null ? new IpGuardProperties() : ipGuard;
    }

    public RateLimitProperties getRateLimit() {
        return rateLimit;
    }

    public void setRateLimit(RateLimitProperties rateLimit) {
        this.rateLimit = rateLimit == null ? new RateLimitProperties() : rateLimit;
    }

    public static class BoundaryPolicyProperties {
        private List<String> publicPaths = new ArrayList<>();
        private List<String> protectedPaths = new ArrayList<>();
        private List<String> adminPaths = new ArrayList<>();
        private List<String> internalPaths = new ArrayList<>();

        public List<String> getPublicPaths() {
            return publicPaths;
        }

        public void setPublicPaths(List<String> publicPaths) {
            this.publicPaths = publicPaths == null ? new ArrayList<>() : publicPaths;
        }

        public List<String> getProtectedPaths() {
            return protectedPaths;
        }

        public void setProtectedPaths(List<String> protectedPaths) {
            this.protectedPaths = protectedPaths == null ? new ArrayList<>() : protectedPaths;
        }

        public List<String> getAdminPaths() {
            return adminPaths;
        }

        public void setAdminPaths(List<String> adminPaths) {
            this.adminPaths = adminPaths == null ? new ArrayList<>() : adminPaths;
        }

        public List<String> getInternalPaths() {
            return internalPaths;
        }

        public void setInternalPaths(List<String> internalPaths) {
            this.internalPaths = internalPaths == null ? new ArrayList<>() : internalPaths;
        }
    }

    public static class AuthProperties {
        private boolean enabled = true;
        private AuthMode defaultMode = AuthMode.HYBRID;
        private boolean allowSessionForBrowser = true;
        private boolean allowBearerForApi = true;
        private boolean allowApiKeyForApi = true;
        private boolean allowHmacForApi = true;
        private boolean allowOidcForApi = true;
        private boolean serviceAccountEnabled = true;
        private boolean internalTokenEnabled = true;
        private boolean defaultModeConfigured = false;
        private boolean allowSessionForBrowserConfigured = false;
        private boolean allowApiKeyForApiConfigured = false;
        private boolean allowHmacForApiConfigured = false;
        private boolean allowOidcForApiConfigured = false;
        private boolean serviceAccountEnabledConfigured = false;
        private boolean internalTokenEnabledConfigured = false;
        private DevFallbackProperties devFallback = new DevFallbackProperties();
        private OidcProperties oidc = new OidcProperties();
        private String jwtSecret = DEFAULT_JWT_SECRET;
        private Duration accessTokenTtl = Duration.ofMinutes(30);
        private Duration refreshTokenTtl = Duration.ofDays(14);

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public AuthMode getDefaultMode() {
            return defaultMode;
        }

        public void setDefaultMode(AuthMode defaultMode) {
            this.defaultModeConfigured = true;
            this.defaultMode = defaultMode == null ? AuthMode.HYBRID : defaultMode;
        }

        public boolean isDefaultModeConfigured() {
            return defaultModeConfigured;
        }

        public void applyDefaultMode(AuthMode defaultMode) {
            this.defaultMode = defaultMode == null ? AuthMode.HYBRID : defaultMode;
        }

        public boolean isAllowSessionForBrowser() {
            return allowSessionForBrowser;
        }

        public void setAllowSessionForBrowser(boolean allowSessionForBrowser) {
            this.allowSessionForBrowserConfigured = true;
            this.allowSessionForBrowser = allowSessionForBrowser;
        }

        public boolean isAllowSessionForBrowserConfigured() {
            return allowSessionForBrowserConfigured;
        }

        public void applyAllowSessionForBrowser(boolean allowSessionForBrowser) {
            this.allowSessionForBrowser = allowSessionForBrowser;
        }

        public boolean isAllowBearerForApi() {
            return allowBearerForApi;
        }

        public void setAllowBearerForApi(boolean allowBearerForApi) {
            this.allowBearerForApi = allowBearerForApi;
        }

        public boolean isAllowApiKeyForApi() {
            return allowApiKeyForApi;
        }

        public void setAllowApiKeyForApi(boolean allowApiKeyForApi) {
            this.allowApiKeyForApiConfigured = true;
            this.allowApiKeyForApi = allowApiKeyForApi;
        }

        public boolean isAllowApiKeyForApiConfigured() {
            return allowApiKeyForApiConfigured;
        }

        public void applyAllowApiKeyForApi(boolean allowApiKeyForApi) {
            this.allowApiKeyForApi = allowApiKeyForApi;
        }

        public boolean isAllowHmacForApi() {
            return allowHmacForApi;
        }

        public void setAllowHmacForApi(boolean allowHmacForApi) {
            this.allowHmacForApiConfigured = true;
            this.allowHmacForApi = allowHmacForApi;
        }

        public boolean isAllowHmacForApiConfigured() {
            return allowHmacForApiConfigured;
        }

        public void applyAllowHmacForApi(boolean allowHmacForApi) {
            this.allowHmacForApi = allowHmacForApi;
        }

        public boolean isAllowOidcForApi() {
            return allowOidcForApi;
        }

        public void setAllowOidcForApi(boolean allowOidcForApi) {
            this.allowOidcForApiConfigured = true;
            this.allowOidcForApi = allowOidcForApi;
        }

        public boolean isAllowOidcForApiConfigured() {
            return allowOidcForApiConfigured;
        }

        public void applyAllowOidcForApi(boolean allowOidcForApi) {
            this.allowOidcForApi = allowOidcForApi;
        }

        public boolean isServiceAccountEnabled() {
            return serviceAccountEnabled;
        }

        public void setServiceAccountEnabled(boolean serviceAccountEnabled) {
            this.serviceAccountEnabledConfigured = true;
            this.serviceAccountEnabled = serviceAccountEnabled;
        }

        public boolean isServiceAccountEnabledConfigured() {
            return serviceAccountEnabledConfigured;
        }

        public void applyServiceAccountEnabled(boolean serviceAccountEnabled) {
            this.serviceAccountEnabled = serviceAccountEnabled;
        }

        public boolean isInternalTokenEnabled() {
            return internalTokenEnabled;
        }

        public void setInternalTokenEnabled(boolean internalTokenEnabled) {
            this.internalTokenEnabledConfigured = true;
            this.internalTokenEnabled = internalTokenEnabled;
        }

        public boolean isInternalTokenEnabledConfigured() {
            return internalTokenEnabledConfigured;
        }

        public void applyInternalTokenEnabled(boolean internalTokenEnabled) {
            this.internalTokenEnabled = internalTokenEnabled;
        }

        public DevFallbackProperties getDevFallback() {
            return devFallback;
        }

        public void setDevFallback(DevFallbackProperties devFallback) {
            this.devFallback = devFallback == null ? new DevFallbackProperties() : devFallback;
        }

        public OidcProperties getOidc() {
            return oidc;
        }

        public void setOidc(OidcProperties oidc) {
            this.oidc = oidc == null ? new OidcProperties() : oidc;
        }

        public String getJwtSecret() {
            return jwtSecret;
        }

        public void setJwtSecret(String jwtSecret) {
            this.jwtSecret = jwtSecret;
        }

        public Duration getAccessTokenTtl() {
            return accessTokenTtl;
        }

        public void setAccessTokenTtl(Duration accessTokenTtl) {
            this.accessTokenTtl = accessTokenTtl == null ? Duration.ofMinutes(30) : accessTokenTtl;
        }

        public Duration getRefreshTokenTtl() {
            return refreshTokenTtl;
        }

        public void setRefreshTokenTtl(Duration refreshTokenTtl) {
            this.refreshTokenTtl = refreshTokenTtl == null ? Duration.ofDays(14) : refreshTokenTtl;
        }
    }

    public static class OperationalPolicyProperties {
        private boolean enabled = true;
        private boolean production = false;
        private List<String> productionProfiles = new ArrayList<>(List.of("prod", "production", "live"));

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public boolean isProduction() {
            return production;
        }

        public void setProduction(boolean production) {
            this.production = production;
        }

        public List<String> getProductionProfiles() {
            return productionProfiles;
        }

        public void setProductionProfiles(List<String> productionProfiles) {
            this.productionProfiles = productionProfiles == null
                    ? new ArrayList<>()
                    : new ArrayList<>(productionProfiles);
        }

        public boolean isProductionProfile(String profile) {
            if (profile == null || profile.isBlank()) {
                return false;
            }
            String normalized = profile.trim();
            for (String productionProfile : productionProfiles) {
                if (productionProfile != null && normalized.equalsIgnoreCase(productionProfile.trim())) {
                    return true;
                }
            }
            return false;
        }
    }

    public static class DevFallbackProperties {
        private boolean enabled = false;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }

    /**
     * token 검증이 끝난 OIDC identity를 principal로 바꿀 때 쓰는 claim mapping 설정이다.
     *
     * <p>이 설정은 token 검증을 설정하지 않는다. issuer, audience, JWK, provider
     * metadata, nonce 검증은 1계층 구현 또는 소비 서비스가 제공하는
     * {@code OidcTokenVerifier}의 책임이다.</p>
     */
    public static class OidcProperties {
        private String principalClaim = "sub";
        private String authoritiesClaim = "roles";
        private String authorityPrefix = "";
        private List<String> defaultAuthorities = new ArrayList<>();

        public String getPrincipalClaim() {
            return principalClaim;
        }

        public void setPrincipalClaim(String principalClaim) {
            this.principalClaim = principalClaim == null || principalClaim.isBlank() ? "sub" : principalClaim.trim();
        }

        public String getAuthoritiesClaim() {
            return authoritiesClaim;
        }

        public void setAuthoritiesClaim(String authoritiesClaim) {
            this.authoritiesClaim = authoritiesClaim == null || authoritiesClaim.isBlank() ? "roles" : authoritiesClaim.trim();
        }

        public String getAuthorityPrefix() {
            return authorityPrefix;
        }

        public void setAuthorityPrefix(String authorityPrefix) {
            this.authorityPrefix = authorityPrefix == null ? "" : authorityPrefix;
        }

        public List<String> getDefaultAuthorities() {
            return defaultAuthorities;
        }

        public void setDefaultAuthorities(List<String> defaultAuthorities) {
            this.defaultAuthorities = defaultAuthorities == null ? new ArrayList<>() : defaultAuthorities;
        }
    }

    public static class IpGuardProperties {
        private boolean enabled = true;
        private boolean trustProxy = true;
        private List<String> adminAllowCidrs = new ArrayList<>();
        private List<String> internalAllowCidrs = new ArrayList<>();

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public boolean isTrustProxy() {
            return trustProxy;
        }

        public void setTrustProxy(boolean trustProxy) {
            this.trustProxy = trustProxy;
        }

        public List<String> getAdminAllowCidrs() {
            return adminAllowCidrs;
        }

        public void setAdminAllowCidrs(List<String> adminAllowCidrs) {
            this.adminAllowCidrs = adminAllowCidrs == null ? new ArrayList<>() : adminAllowCidrs;
        }

        public List<String> getInternalAllowCidrs() {
            return internalAllowCidrs;
        }

        public void setInternalAllowCidrs(List<String> internalAllowCidrs) {
            this.internalAllowCidrs = internalAllowCidrs == null ? new ArrayList<>() : internalAllowCidrs;
        }
    }

    public static class RateLimitProperties {
        private boolean enabled = true;
        private BoundaryRateLimitPolicyProperties anonymous = new BoundaryRateLimitPolicyProperties();
        private BoundaryRateLimitPolicyProperties authenticated = new BoundaryRateLimitPolicyProperties();
        private BoundaryRateLimitPolicyProperties internal = new BoundaryRateLimitPolicyProperties();
        private List<RouteRateLimitPolicyProperties> routes = new ArrayList<>();

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public BoundaryRateLimitPolicyProperties getAnonymous() {
            return anonymous;
        }

        public void setAnonymous(BoundaryRateLimitPolicyProperties anonymous) {
            this.anonymous = anonymous == null ? new BoundaryRateLimitPolicyProperties() : anonymous;
        }

        public BoundaryRateLimitPolicyProperties getAuthenticated() {
            return authenticated;
        }

        public void setAuthenticated(BoundaryRateLimitPolicyProperties authenticated) {
            this.authenticated = authenticated == null ? new BoundaryRateLimitPolicyProperties() : authenticated;
        }

        public BoundaryRateLimitPolicyProperties getInternal() {
            return internal;
        }

        public void setInternal(BoundaryRateLimitPolicyProperties internal) {
            this.internal = internal == null ? new BoundaryRateLimitPolicyProperties() : internal;
        }

        public List<RouteRateLimitPolicyProperties> getRoutes() {
            return routes;
        }

        public void setRoutes(List<RouteRateLimitPolicyProperties> routes) {
            this.routes = routes == null ? new ArrayList<>() : routes;
        }
    }

    public static class BoundaryRateLimitPolicyProperties {
        private long requests = 100L;
        private long windowSeconds = 60L;

        public long getRequests() {
            return requests;
        }

        public void setRequests(long requests) {
            this.requests = requests;
        }

        public long getWindowSeconds() {
            return windowSeconds;
        }

        public void setWindowSeconds(long windowSeconds) {
            this.windowSeconds = windowSeconds;
        }
    }

    public static class RouteRateLimitPolicyProperties extends BoundaryRateLimitPolicyProperties {
        private String name = "route";
        private List<String> patterns = new ArrayList<>();

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name == null || name.isBlank() ? "route" : name.trim();
        }

        public List<String> getPatterns() {
            return patterns;
        }

        public void setPatterns(List<String> patterns) {
            this.patterns = patterns == null ? new ArrayList<>() : patterns;
        }
    }
}
