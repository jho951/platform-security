package io.github.jho951.platform.security.policy;

import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityContext;

public interface ClientTypeResolver {
    ClientType resolve(SecurityRequest request);

    default ClientType resolve(SecurityRequest request, SecurityContext context, SecurityBoundary boundary) {
        return resolve(request);
    }
}
