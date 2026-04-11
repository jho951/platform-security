package io.github.jho951.platform.security.api;

import java.util.List;
import java.util.Objects;

public record ResolvedSecurityProfile(
        String boundaryType,
        List<String> boundaryPatterns,
        String clientType,
        String authMode
) {
    public ResolvedSecurityProfile {
        boundaryType = requireText(boundaryType, "boundaryType").toUpperCase();
        boundaryPatterns = boundaryPatterns == null ? List.of() : List.copyOf(boundaryPatterns);
        clientType = requireText(clientType, "clientType").toUpperCase();
        authMode = requireText(authMode, "authMode").toUpperCase();
    }

    private static String requireText(String value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) throw new IllegalArgumentException(field + " must not be blank");
        return value.trim();
    }
}
