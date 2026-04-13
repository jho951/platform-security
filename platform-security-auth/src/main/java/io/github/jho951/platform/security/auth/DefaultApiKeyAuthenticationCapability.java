package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.apikey.ApiKeyAuthenticationProvider;
import com.auth.apikey.ApiKeyCredential;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public final class DefaultApiKeyAuthenticationCapability implements AuthenticationCapability {
    private final ApiKeyAuthenticationProvider apiKeyAuthenticationProvider;

    public DefaultApiKeyAuthenticationCapability(ApiKeyAuthenticationProvider apiKeyAuthenticationProvider) {
        this.apiKeyAuthenticationProvider = Objects.requireNonNull(apiKeyAuthenticationProvider, "apiKeyAuthenticationProvider");
    }

    @Override
    public String name() {
        return "api-key";
    }

    @Override
    public Optional<Principal> authenticate(SecurityRequest request) {
        Map<String, String> attributes = request.attributes();
        String keyId = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.API_KEY_ID_ATTRIBUTE));
        String secret = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.API_KEY_SECRET_ATTRIBUTE));
        if (keyId == null || secret == null) {
            return Optional.empty();
        }
        return apiKeyAuthenticationProvider.authenticate(new ApiKeyCredential(keyId, secret));
    }
}
