package io.github.jho951.platform.security.auth;

import java.util.Optional;

/**
 * token/session credential 검증을 platform 소유 경계로 감싼 port다.
 */
public interface PlatformSessionSupport {

    Optional<PlatformAuthenticatedPrincipal> authenticate(String accessToken, String sessionId);

    default Optional<PlatformAuthenticatedPrincipal> authenticateAccessToken(String accessToken) {
        return authenticate(accessToken, null);
    }

    default Optional<PlatformAuthenticatedPrincipal> authenticateSession(String sessionId) {
        return authenticate(null, sessionId);
    }
}
