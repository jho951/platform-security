package io.github.jho951.platform.security.policy;

import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.ResolvedSecurityProfile;

public interface BoundaryIpPolicyProvider {
    SecurityPolicy resolve(SecurityBoundary boundary);

    default SecurityPolicy resolve(SecurityBoundary boundary, ResolvedSecurityProfile profile) {
        return resolve(boundary);
    }
}
