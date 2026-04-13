package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import io.github.jho951.platform.security.api.SecurityRequest;

@FunctionalInterface
public interface InternalTokenClaimsValidator {
    boolean validate(Principal principal, SecurityRequest request);

    static InternalTokenClaimsValidator allowAll() {
        return (principal, request) -> principal != null;
    }
}
