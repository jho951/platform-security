package io.github.jho951.platform.security.autoconfigure;

import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class PlatformJwtAuthorityConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    private final PlatformSecurityProperties.AuthProperties properties;

    PlatformJwtAuthorityConverter(PlatformSecurityProperties.AuthProperties properties) {
        this.properties = properties == null ? new PlatformSecurityProperties.AuthProperties() : properties;
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        addRoleAuthorities(jwt, authorities);
        addScopeAuthorities(jwt, authorities);
        addStatusAuthorities(jwt, authorities);
        return authorities;
    }

    private void addRoleAuthorities(Jwt jwt, Set<GrantedAuthority> authorities) {
        Object roleClaim = jwt.getClaims().get(properties.getJwtRoleClaim());
        if (roleClaim instanceof String role && !role.isBlank()) {
            authorities.add(new SimpleGrantedAuthority(toRoleAuthority(role)));
        }

        Object rolesClaim = jwt.getClaims().get(properties.getJwtRolesClaim());
        if (rolesClaim instanceof List<?> roles) {
            roles.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .map(this::toRoleAuthority)
                    .map(SimpleGrantedAuthority::new)
                    .forEach(authorities::add);
        }
    }

    private void addScopeAuthorities(Jwt jwt, Set<GrantedAuthority> authorities) {
        Object scopeClaim = jwt.getClaims().get("scope");
        if (scopeClaim instanceof String scope && !scope.isBlank()) {
            for (String value : scope.split("\\s+")) {
                if (!value.isBlank()) {
                    authorities.add(new SimpleGrantedAuthority("SCOPE_" + value));
                }
            }
        }

        Object scpClaim = jwt.getClaims().get("scp");
        if (scpClaim instanceof List<?> scopes) {
            scopes.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .filter(scope -> !scope.isBlank())
                    .map(scope -> "SCOPE_" + scope)
                    .map(SimpleGrantedAuthority::new)
                    .forEach(authorities::add);
        }
    }

    private void addStatusAuthorities(Jwt jwt, Set<GrantedAuthority> authorities) {
        String status = trimToNull(jwt.getClaimAsString(properties.getJwtStatusClaim()));
        PlatformSecurityProperties.GatewayHeaderProperties gatewayHeader = properties.getGatewayHeader();
        if (status == null || gatewayHeader == null) {
            return;
        }
        addAuthority(authorities, gatewayHeader.getStatusAuthorityPrefix() + status);
        String activeStatus = trimToNull(gatewayHeader.getActiveStatus());
        if (activeStatus != null && status.equalsIgnoreCase(activeStatus)) {
            addAuthority(authorities, gatewayHeader.getActiveStatusAuthority());
        }
    }

    private String toRoleAuthority(String role) {
        String value = role.trim();
        if (value.startsWith("ROLE_") || value.startsWith("SCOPE_")) {
            return value;
        }
        return "ROLE_" + value;
    }

    private static void addAuthority(Set<GrantedAuthority> authorities, String authority) {
        String value = trimToNull(authority);
        if (value != null) {
            authorities.add(new SimpleGrantedAuthority(value));
        }
    }

    private static String trimToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }
}
