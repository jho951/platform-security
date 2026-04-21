package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * bearer access token을 처리하는 JWT capability다.
 *
 * <p>JWT parse와 서명 검증은 platform session support port에 위임한다.</p>
 */
public final class DefaultJwtAuthenticationCapability implements AuthenticationCapability {
    private final PlatformSessionSupport platformSessionSupport;

    /**
     * JWT 검증 provider와 capability를 연결한다.
     *
     * @param platformSessionSupport access token 검증 port
     */
    public DefaultJwtAuthenticationCapability(PlatformSessionSupport platformSessionSupport) {
        this.platformSessionSupport = Objects.requireNonNull(platformSessionSupport, "platformSessionSupport");
    }

    @Override
    public String name() {
        return "jwt";
    }

    @Override
    public Optional<Principal> authenticate(SecurityRequest request) {
        return authenticate(request.attributes());
    }

    Optional<Principal> authenticate(Map<String, String> attributes) {
        String accessToken = trimToNull(attributes.get(PlatformAuthenticationFacade.ACCESS_TOKEN_ATTRIBUTE));
        if (accessToken == null) {
            return Optional.empty();
        }
        return platformSessionSupport.authenticateAccessToken(accessToken);
    }

    static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
