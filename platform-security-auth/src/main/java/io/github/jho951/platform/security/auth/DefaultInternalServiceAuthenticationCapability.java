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
    private final InternalTokenClaimsValidator claimsValidator;

    public DefaultInternalServiceAuthenticationCapability(HybridAuthenticationProvider hybridAuthenticationProvider) {
        this(hybridAuthenticationProvider, InternalTokenClaimsValidator.allowAll());
    }

    public DefaultInternalServiceAuthenticationCapability(
            HybridAuthenticationProvider hybridAuthenticationProvider,
            InternalTokenClaimsValidator claimsValidator
    ) {
        this.hybridAuthenticationProvider = Objects.requireNonNull(hybridAuthenticationProvider, "hybridAuthenticationProvider");
        this.claimsValidator = Objects.requireNonNull(claimsValidator, "claimsValidator");
    }

    @Override
    public String name() {
        return "internal";
    }

    @Override
    public Optional<Principal> authenticate(SecurityRequest request) {
        return doAuthenticate(request);
    }

    Optional<Principal> doAuthenticate(SecurityRequest request) {
        Map<String, String> attributes = request.attributes();
        String internalToken = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(INTERNAL_TOKEN_ATTRIBUTE));
        String sessionId = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.SESSION_ID_ATTRIBUTE));
        if (internalToken == null && sessionId == null) {
            return Optional.empty();
        }
        Principal principal = hybridAuthenticationProvider.authenticate(HybridAuthenticationContext.of(internalToken, sessionId)).orElse(null);
        if (principal != null && !claimsValidator.validate(principal, request)) {
            return Optional.empty();
        }
        return Optional.ofNullable(principal);
    }
}
