package io.github.jho951.platform.security.auth;

/**
 * 발급된 token view다.
 */
public record PlatformIssuedToken(
        String accessToken,
        String refreshToken
) {
    public PlatformIssuedToken {
        accessToken = blankToNull(accessToken);
        refreshToken = blankToNull(refreshToken);
    }

    public boolean hasAnyToken() {
        return accessToken != null || refreshToken != null;
    }

    private static String blankToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
