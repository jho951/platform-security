package io.github.jho951.platform.security.auth;

import io.github.jho951.platform.security.policy.AuthMode;

public interface AuthenticationCapabilityResolver {
    AuthenticationCapability resolve(AuthMode authMode);

    default AuthenticationCapability resolve(AuthMode authMode, boolean internalService) {
        return resolve(authMode);
    }
}
