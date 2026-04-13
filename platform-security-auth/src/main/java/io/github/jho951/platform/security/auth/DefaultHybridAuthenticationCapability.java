package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.hybrid.HybridAuthenticationContext;
import com.auth.hybrid.HybridAuthenticationProvider;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * access token과 session id를 함께 허용하는 hybrid 인증 capability다.
 *
 * <p>2계층은 request attributes에서 credential을 꺼내는 역할만 수행하고, 실제
 * token/session 검증은 {@link HybridAuthenticationProvider}에 위임한다.</p>
 */
public final class DefaultHybridAuthenticationCapability implements AuthenticationCapability {
    private final HybridAuthenticationProvider hybridAuthenticationProvider;

    /**
     * hybrid provider와 capability를 연결한다.
     *
     * @param hybridAuthenticationProvider token/session 검증 provider
     */
    public DefaultHybridAuthenticationCapability(HybridAuthenticationProvider hybridAuthenticationProvider) {
        this.hybridAuthenticationProvider = Objects.requireNonNull(hybridAuthenticationProvider, "hybridAuthenticationProvider");
    }

    @Override
    public String name() {
        return "hybrid";
    }

    @Override
    public Optional<Principal> authenticate(SecurityRequest request) {
        return authenticate(request.attributes());
    }

    Optional<Principal> authenticate(Map<String, String> attributes) {
        String accessToken = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.ACCESS_TOKEN_ATTRIBUTE));
        String sessionId = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.SESSION_ID_ATTRIBUTE));
        if (accessToken == null && sessionId == null) {
            return Optional.empty();
        }
        Principal principal = hybridAuthenticationProvider.authenticate(HybridAuthenticationContext.of(accessToken, sessionId)).orElse(null);
        return Optional.ofNullable(principal);
    }
}
