package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.oidc.OidcIdentity;
import com.auth.oidc.OidcPrincipalMapper;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class DefaultOidcPrincipalMapper implements OidcPrincipalMapper {
    private final PlatformSecurityProperties.OidcProperties properties;

    public DefaultOidcPrincipalMapper(PlatformSecurityProperties.OidcProperties properties) {
        this.properties = properties == null ? new PlatformSecurityProperties.OidcProperties() : properties;
    }

    @Override
    public Principal map(OidcIdentity identity) {
        Objects.requireNonNull(identity, "identity");
        Map<String, Object> claims = identity.claims() == null ? Map.of() : identity.claims();
        String principal = claimAsString(claims.get(properties.getPrincipalClaim()));
        if (principal == null) {
            principal = identity.subject();
        }
        Map<String, Object> attributes = new LinkedHashMap<>(claims);
        attributes.putIfAbsent("issuer", identity.issuer());
        attributes.putIfAbsent("audience", identity.audience());
        return new Principal(principal, authorities(claims), attributes);
    }

    private List<String> authorities(Map<String, Object> claims) {
        List<String> authorities = new ArrayList<>();
        Object value = claims.get(properties.getAuthoritiesClaim());
        if (value instanceof Collection<?> collection) {
            collection.forEach(item -> addAuthority(authorities, item));
        } else if (value instanceof String string) {
            for (String item : string.split(",")) {
                addAuthority(authorities, item);
            }
        }
        properties.getDefaultAuthorities().forEach(item -> addAuthority(authorities, item));
        return List.copyOf(authorities);
    }

    private void addAuthority(List<String> authorities, Object value) {
        String authority = claimAsString(value);
        if (authority == null) {
            return;
        }
        String prefixed = properties.getAuthorityPrefix() + authority;
        if (!authorities.contains(prefixed)) {
            authorities.add(prefixed);
        }
    }

    private String claimAsString(Object value) {
        if (value == null) {
            return null;
        }
        String string = String.valueOf(value).trim();
        return string.isEmpty() ? null : string;
    }
}
