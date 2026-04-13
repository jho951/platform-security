package io.github.jho951.platform.security.policy;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public class PlatformSecurityProperties {
    private boolean enabled = true;
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
        private DevFallbackProperties devFallback = new DevFallbackProperties();
        private String jwtSecret = "platform-security-dev-secret-platform-security-dev-secret";
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
            this.defaultMode = defaultMode == null ? AuthMode.HYBRID : defaultMode;
        }

        public boolean isAllowSessionForBrowser() {
            return allowSessionForBrowser;
        }

        public void setAllowSessionForBrowser(boolean allowSessionForBrowser) {
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
            this.allowApiKeyForApi = allowApiKeyForApi;
        }

        public boolean isAllowHmacForApi() {
            return allowHmacForApi;
        }

        public void setAllowHmacForApi(boolean allowHmacForApi) {
            this.allowHmacForApi = allowHmacForApi;
        }

        public boolean isAllowOidcForApi() {
            return allowOidcForApi;
        }

        public void setAllowOidcForApi(boolean allowOidcForApi) {
            this.allowOidcForApi = allowOidcForApi;
        }

        public boolean isServiceAccountEnabled() {
            return serviceAccountEnabled;
        }

        public void setServiceAccountEnabled(boolean serviceAccountEnabled) {
            this.serviceAccountEnabled = serviceAccountEnabled;
        }

        public boolean isInternalTokenEnabled() {
            return internalTokenEnabled;
        }

        public void setInternalTokenEnabled(boolean internalTokenEnabled) {
            this.internalTokenEnabled = internalTokenEnabled;
        }

        public DevFallbackProperties getDevFallback() {
            return devFallback;
        }

        public void setDevFallback(DevFallbackProperties devFallback) {
            this.devFallback = devFallback == null ? new DevFallbackProperties() : devFallback;
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

    public static class DevFallbackProperties {
        private boolean enabled = false;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
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
