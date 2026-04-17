package io.github.jho951.platform.security.local;

import com.auth.api.model.Principal;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.auth.InternalTokenClaimsValidator;

/**
 * local/test 전용 internal token claim validator다.
 */
public final class LocalInternalTokenClaimsValidator implements InternalTokenClaimsValidator {
    @Override
    public boolean validate(Principal principal, SecurityRequest request) {
        return principal != null;
    }
}
