package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityRequest;

public interface SecurityContextResolver {
    SecurityContext resolve(SecurityRequest request);
}
