package io.github.jho951.platform.security.web;

import java.util.Objects;

public final class SecurityBoundaryResolver {
    public String resolve(String requestPath) {
        Objects.requireNonNull(requestPath, "requestPath");
        String normalized = requestPath.trim();
        if (normalized.isEmpty()) throw new IllegalArgumentException("requestPath must not be blank");
        return normalized.startsWith("/") ? normalized : "/" + normalized;
    }
}
