package io.github.jho951.platform.security.auth;

import com.auth.api.model.OAuth2UserIdentity;
import com.auth.api.model.Principal;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;

final class AuthPrincipalAdapters {
    private AuthPrincipalAdapters() {
    }

    static PlatformAuthenticatedPrincipal toPlatform(Principal principal) {
        Objects.requireNonNull(principal, "principal");
        return new PlatformAuthenticatedPrincipal(
                principal.getUserId(),
                new LinkedHashSet<>(principal.getAuthorities()),
                new LinkedHashMap<>(principal.getAttributes())
        );
    }

    static Principal toAuth(PlatformAuthenticatedPrincipal principal) {
        Objects.requireNonNull(principal, "principal");
        return new Principal(
                principal.userId(),
                new java.util.ArrayList<>(principal.authorities()),
                new LinkedHashMap<>(principal.attributes())
        );
    }

    static OAuth2UserIdentity toAuth(PlatformOAuth2UserIdentity identity) {
        Objects.requireNonNull(identity, "identity");
        return new OAuth2UserIdentity(
                identity.provider(),
                identity.providerUserId(),
                identity.email(),
                identity.displayName(),
                copy(identity.attributes())
        );
    }

    private static Map<String, Object> copy(Map<String, Object> attributes) {
        return attributes == null ? Map.of() : new LinkedHashMap<>(attributes);
    }
}
