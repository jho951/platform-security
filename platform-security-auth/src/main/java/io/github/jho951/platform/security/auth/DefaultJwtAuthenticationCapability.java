package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.hybrid.HybridAuthenticationContext;
import com.auth.hybrid.HybridAuthenticationProvider;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * bearer access token을 처리하는 JWT capability다.
 *
 * <p>JWT parse와 서명 검증은 1계층 {@link HybridAuthenticationProvider}로 위임한다.</p>
 */
public final class DefaultJwtAuthenticationCapability implements AuthenticationCapability {
    private final HybridAuthenticationProvider hybridAuthenticationProvider;

    /**
     * JWT 검증 provider와 capability를 연결한다.
     *
     * @param hybridAuthenticationProvider access token 검증 provider
     */
    public DefaultJwtAuthenticationCapability(HybridAuthenticationProvider hybridAuthenticationProvider) {
        this.hybridAuthenticationProvider = Objects.requireNonNull(hybridAuthenticationProvider, "hybridAuthenticationProvider");
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
        Principal principal = hybridAuthenticationProvider.authenticate(HybridAuthenticationContext.of(accessToken, null)).orElse(null);
        return Optional.ofNullable(principal);
    }

    static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
