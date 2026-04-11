package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.hybrid.HybridAuthenticationContext;
import com.auth.hybrid.HybridAuthenticationProvider;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public final class DefaultInternalServiceAuthenticationCapability implements AuthenticationCapability {
    public static final String INTERNAL_TOKEN_ATTRIBUTE = "auth.internalToken";

    private final HybridAuthenticationProvider hybridAuthenticationProvider;

    public DefaultInternalServiceAuthenticationCapability(HybridAuthenticationProvider hybridAuthenticationProvider) {
        this.hybridAuthenticationProvider = Objects.requireNonNull(hybridAuthenticationProvider, "hybridAuthenticationProvider");
    }

    @Override
    public String name() {
        return "internal";
    }

    @Override
    public Optional<Principal> authenticate(SecurityRequest request) {
        return authenticate(request.attributes());
    }

    Optional<Principal> authenticate(Map<String, String> attributes) {
        String internalToken = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(INTERNAL_TOKEN_ATTRIBUTE));
        String sessionId = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.SESSION_ID_ATTRIBUTE));
        if (internalToken == null && sessionId == null) {
            return Optional.empty();
        }
        Principal principal = hybridAuthenticationProvider.authenticate(HybridAuthenticationContext.of(internalToken, sessionId)).orElse(null);
        return Optional.ofNullable(principal);
    }
}
