package io.github.jho951.platform.security.auth;

/**
 * 서비스가 로그인을 승인한 뒤 발급된 token/session 값 묶음이다.
 *
 * <p>사용한 issuance capability에 따라 일부 값은 없을 수 있다. 예를 들어 token-only
 * flow는 {@link #sessionId()}가 없을 수 있고, session-only flow는 token 값이 없을 수
 * 있다.</p>
 */
public record PlatformTokenBundle(
        String accessToken,
        String refreshToken,
        String sessionId
) {
    /**
     * 빈 문자열 credential은 null로 정규화한다.
     *
     * @param accessToken 발급된 access token
     * @param refreshToken 발급된 refresh token
     * @param sessionId 발급된 session id
     */
    public PlatformTokenBundle {
        accessToken = blankToNull(accessToken);
        refreshToken = blankToNull(refreshToken);
        sessionId = blankToNull(sessionId);
    }

    /**
     * 호출자가 사용할 credential이 하나라도 있는지 확인한다.
     *
     * @return access token, refresh token, session id 중 하나라도 있으면 true
     */
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
