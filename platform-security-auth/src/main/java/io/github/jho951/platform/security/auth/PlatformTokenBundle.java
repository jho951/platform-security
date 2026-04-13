package io.github.jho951.platform.security.auth;

public record PlatformTokenBundle(
        String accessToken,
        String refreshToken,
        String sessionId
) {
    public PlatformTokenBundle {
        accessToken = blankToNull(accessToken);
        refreshToken = blankToNull(refreshToken);
        sessionId = blankToNull(sessionId);
    }

    public boolean hasAnyCredential() {
        return accessToken != null || refreshToken != null || sessionId != null;
    }

    private static String blankToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
