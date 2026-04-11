package io.github.jho951.platform.security.policy;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityRequest;

public interface AuthenticationModeResolver {
    AuthMode resolve(SecurityRequest request, SecurityContext context);

    default AuthMode resolve(SecurityRequest request, SecurityContext context, SecurityBoundary boundary, ClientType clientType) {
        return resolve(request, context);
    }
}
