package io.github.jho951.platform.security.auth;

import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * access token과 session id를 함께 허용하는 hybrid 인증 capability다.
 *
 * <p>2계층은 request attributes에서 credential을 꺼내는 역할만 수행하고, 실제
 * token/session 검증은 platform session support port에 위임한다.</p>
 */
public final class DefaultHybridAuthenticationCapability implements AuthenticationCapability {
    private final PlatformSessionSupport platformSessionSupport;

    /**
     * hybrid provider와 capability를 연결한다.
     *
     * @param platformSessionSupport token/session 검증 port
     */
    public DefaultHybridAuthenticationCapability(PlatformSessionSupport platformSessionSupport) {
        this.platformSessionSupport = Objects.requireNonNull(platformSessionSupport, "platformSessionSupport");
    }

    @Override
    public String name() {
        return "hybrid";
    }

    @Override
    public Optional<PlatformAuthenticatedPrincipal> authenticate(SecurityRequest request) {
        return authenticate(request.attributes());
    }

    Optional<PlatformAuthenticatedPrincipal> authenticate(Map<String, String> attributes) {
        String accessToken = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.ACCESS_TOKEN_ATTRIBUTE));
        String sessionId = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.SESSION_ID_ATTRIBUTE));
        if (accessToken == null && sessionId == null) {
            return Optional.empty();
        }
        return platformSessionSupport.authenticate(accessToken, sessionId);
    }
}
