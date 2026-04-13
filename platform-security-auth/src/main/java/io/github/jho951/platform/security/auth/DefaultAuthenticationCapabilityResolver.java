package io.github.jho951.platform.security.auth;

import io.github.jho951.platform.security.policy.AuthMode;

import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

public final class DefaultAuthenticationCapabilityResolver implements AuthenticationCapabilityResolver {
    private static final AuthenticationCapability NO_OP_CAPABILITY = new AuthenticationCapability() {
        @Override
        public String name() {
            return "none";
        }

        @Override
        public java.util.Optional<com.auth.api.model.Principal> authenticate(io.github.jho951.platform.security.api.SecurityRequest request) {
            return java.util.Optional.empty();
        }
    };

    private final Map<AuthMode, AuthenticationCapability> capabilities = new EnumMap<>(AuthMode.class);
    private final AuthenticationCapability internalCapability;

    public DefaultAuthenticationCapabilityResolver(
            AuthenticationCapability jwtCapability,
            AuthenticationCapability sessionCapability,
            AuthenticationCapability hybridCapability,
            AuthenticationCapability internalCapability
    ) {
        capabilities.put(AuthMode.JWT, Objects.requireNonNull(jwtCapability, "jwtCapability"));
        capabilities.put(AuthMode.SESSION, Objects.requireNonNull(sessionCapability, "sessionCapability"));
        capabilities.put(AuthMode.HYBRID, Objects.requireNonNull(hybridCapability, "hybridCapability"));
        capabilities.put(AuthMode.NONE, NO_OP_CAPABILITY);
        this.internalCapability = Objects.requireNonNull(internalCapability, "internalCapability");
    }

    public DefaultAuthenticationCapabilityResolver(
            AuthenticationCapability jwtCapability,
            AuthenticationCapability sessionCapability,
            AuthenticationCapability hybridCapability,
            AuthenticationCapability internalCapability,
            AuthenticationCapability apiKeyCapability,
            AuthenticationCapability hmacCapability,
            AuthenticationCapability oidcCapability,
            AuthenticationCapability serviceAccountCapability
    ) {
        this(jwtCapability, sessionCapability, hybridCapability, internalCapability);
        putIfPresent(AuthMode.API_KEY, apiKeyCapability);
        putIfPresent(AuthMode.HMAC, hmacCapability);
        putIfPresent(AuthMode.OIDC, oidcCapability);
        putIfPresent(AuthMode.SERVICE_ACCOUNT, serviceAccountCapability);
    }

    @Override
    public AuthenticationCapability resolve(AuthMode authMode) {
        return capabilities.getOrDefault(authMode, capabilities.get(AuthMode.NONE));
    }

    @Override
    public AuthenticationCapability resolve(AuthMode authMode, boolean internalService) {
        if (internalService) {
            return internalCapability;
        }
        return resolve(authMode);
    }

    private void putIfPresent(AuthMode authMode, AuthenticationCapability capability) {
        if (capability != null) {
            capabilities.put(authMode, capability);
        }
    }
}
