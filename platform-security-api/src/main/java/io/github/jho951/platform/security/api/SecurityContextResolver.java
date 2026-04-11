package io.github.jho951.platform.security.api;

public interface SecurityContextResolver {
    SecurityContext resolve(SecurityRequest request);
}
