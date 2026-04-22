package io.github.jho951.platform.security.auth;

import java.util.Objects;

/**
 * session 조회/발급 결과 view다.
 */
public record PlatformSessionView(
        String sessionId,
        PlatformAuthenticatedPrincipal principal
) {
    public PlatformSessionView {
        if (sessionId == null || sessionId.isBlank()) {
            throw new IllegalArgumentException("sessionId must not be blank");
        }
        sessionId = sessionId.trim();
        principal = Objects.requireNonNull(principal, "principal");
    }
}
