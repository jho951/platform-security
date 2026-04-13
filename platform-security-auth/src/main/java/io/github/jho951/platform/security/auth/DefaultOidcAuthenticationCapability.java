package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.oidc.OidcAuthenticationProvider;
import com.auth.oidc.OidcAuthenticationRequest;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public final class DefaultOidcAuthenticationCapability implements AuthenticationCapability {
    private final OidcAuthenticationProvider oidcAuthenticationProvider;

    public DefaultOidcAuthenticationCapability(OidcAuthenticationProvider oidcAuthenticationProvider) {
        this.oidcAuthenticationProvider = Objects.requireNonNull(oidcAuthenticationProvider, "oidcAuthenticationProvider");
    }

    @Override
    public String name() {
        return "oidc";
    }

    @Override
    public Optional<Principal> authenticate(SecurityRequest request) {
        Map<String, String> attributes = request.attributes();
        String idToken = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.OIDC_ID_TOKEN_ATTRIBUTE));
        if (idToken == null) {
            return Optional.empty();
        }
        String nonce = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.OIDC_NONCE_ATTRIBUTE));
        try {
            return oidcAuthenticationProvider.authenticate(new OidcAuthenticationRequest(idToken, nonce));
        } catch (RuntimeException ex) {
            return Optional.empty();
        }
    }
}
