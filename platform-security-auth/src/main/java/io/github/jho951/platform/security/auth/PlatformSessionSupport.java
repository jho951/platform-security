package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;

import java.util.Optional;

/**
 * token/session credential 검증을 platform 소유 경계로 감싼 port다.
 */
public interface PlatformSessionSupport {

    Optional<Principal> authenticate(String accessToken, String sessionId);

    default Optional<Principal> authenticateAccessToken(String accessToken) {
        return authenticate(accessToken, null);
    }

    default Optional<Principal> authenticateSession(String sessionId) {
        return authenticate(null, sessionId);
    }
}
