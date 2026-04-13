package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.serviceaccount.ServiceAccountAuthenticationProvider;
import com.auth.serviceaccount.ServiceAccountCredential;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public final class DefaultServiceAccountAuthenticationCapability implements AuthenticationCapability {
    private final ServiceAccountAuthenticationProvider serviceAccountAuthenticationProvider;

    public DefaultServiceAccountAuthenticationCapability(ServiceAccountAuthenticationProvider serviceAccountAuthenticationProvider) {
        this.serviceAccountAuthenticationProvider = Objects.requireNonNull(serviceAccountAuthenticationProvider, "serviceAccountAuthenticationProvider");
    }

    @Override
    public String name() {
        return "service-account";
    }

    @Override
    public Optional<Principal> authenticate(SecurityRequest request) {
        Map<String, String> attributes = request.attributes();
        String serviceId = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.SERVICE_ACCOUNT_ID_ATTRIBUTE));
        String secret = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.SERVICE_ACCOUNT_SECRET_ATTRIBUTE));
        if (serviceId == null || secret == null) {
            return Optional.empty();
        }
        return serviceAccountAuthenticationProvider.authenticate(new ServiceAccountCredential(serviceId, secret));
    }
}
