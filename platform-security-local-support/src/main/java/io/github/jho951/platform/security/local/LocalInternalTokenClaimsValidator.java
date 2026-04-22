package io.github.jho951.platform.security.local;

import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.auth.InternalTokenClaimsValidator;
import io.github.jho951.platform.security.auth.PlatformAuthenticatedPrincipal;

/**
 * local/test 전용 internal token claim validator다.
 */
public final class LocalInternalTokenClaimsValidator implements InternalTokenClaimsValidator {
    @Override
    public boolean validate(PlatformAuthenticatedPrincipal principal, SecurityRequest request) {
        return principal != null;
    }
}
