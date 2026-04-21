package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * session id를 처리하는 session capability다.
 *
 * <p>session 조회와 principal 복원은 platform session support port로
 * 위임한다.</p>
 */
public final class DefaultSessionAuthenticationCapability implements AuthenticationCapability {
    private final PlatformSessionSupport platformSessionSupport;

    /**
     * session 검증 provider와 capability를 연결한다.
     *
     * @param platformSessionSupport session 검증 port
     */
    public DefaultSessionAuthenticationCapability(PlatformSessionSupport platformSessionSupport) {
        this.platformSessionSupport = Objects.requireNonNull(platformSessionSupport, "platformSessionSupport");
    }

    @Override
    public String name() {
        return "session";
    }

    @Override
    public Optional<Principal> authenticate(SecurityRequest request) {
        return authenticate(request.attributes());
    }

    Optional<Principal> authenticate(Map<String, String> attributes) {
        String sessionId = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.SESSION_ID_ATTRIBUTE));
        if (sessionId == null) {
            return Optional.empty();
        }
        return platformSessionSupport.authenticateSession(sessionId);
    }
}
