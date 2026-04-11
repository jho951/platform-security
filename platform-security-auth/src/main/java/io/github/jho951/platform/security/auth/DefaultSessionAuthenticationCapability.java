package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.hybrid.HybridAuthenticationContext;
import com.auth.hybrid.HybridAuthenticationProvider;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public final class DefaultSessionAuthenticationCapability implements AuthenticationCapability {
    private final HybridAuthenticationProvider hybridAuthenticationProvider;

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
