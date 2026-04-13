package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.hybrid.HybridAuthenticationContext;
import com.auth.hybrid.HybridAuthenticationProvider;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * session id를 처리하는 session capability다.
 *
 * <p>session 조회와 principal 복원은 1계층 {@link HybridAuthenticationProvider}로
 * 위임한다.</p>
 */
public final class DefaultSessionAuthenticationCapability implements AuthenticationCapability {
    private final HybridAuthenticationProvider hybridAuthenticationProvider;

    /**
     * session 검증 provider와 capability를 연결한다.
     *
     * @param hybridAuthenticationProvider session 검증 provider
     */
    public DefaultSessionAuthenticationCapability(HybridAuthenticationProvider hybridAuthenticationProvider) {
        this.hybridAuthenticationProvider = Objects.requireNonNull(hybridAuthenticationProvider, "hybridAuthenticationProvider");
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
        Principal principal = hybridAuthenticationProvider.authenticate(HybridAuthenticationContext.of(null, sessionId)).orElse(null);
        return Optional.ofNullable(principal);
    }
}
