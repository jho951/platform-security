package io.github.jho951.platform.security.policy;

import io.github.jho951.platform.security.api.SecurityRequest;

public interface SecurityBoundaryResolver {
    SecurityBoundary resolve(SecurityRequest request);
}
