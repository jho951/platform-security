package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.hybrid.DefaultHybridAuthenticationProvider;
import com.auth.hybrid.HybridAuthenticationContext;
import com.auth.hybrid.HybridAuthenticationProvider;
import com.auth.session.DefaultSessionAuthenticationProvider;
import com.auth.session.IdentitySessionPrincipalMapper;
import com.auth.session.SessionPrincipalMapper;
import com.auth.session.SessionStore;
import com.auth.session.SimpleSessionStore;
import com.auth.spi.TokenService;
import com.auth.support.jwt.JwtTokenService;
import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.web.SecurityContextResolver;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public final class AuthServerSecurityContextResolver implements SecurityContextResolver {
    public static final String AUTHENTICATED_ATTRIBUTE = "auth.authenticated";
    public static final String PRINCIPAL_ATTRIBUTE = "auth.principal";
    public static final String ROLES_ATTRIBUTE = "auth.roles";
    public static final String ACCESS_TOKEN_ATTRIBUTE = AuthServerHeaderNames.ACCESS_TOKEN_ATTRIBUTE;
    public static final String SESSION_ID_ATTRIBUTE = AuthServerHeaderNames.SESSION_ID_ATTRIBUTE;

    private final HybridAuthenticationProvider hybridAuthenticationProvider;

    public AuthServerSecurityContextResolver() {
        this("platform-security-dev-secret-platform-security-dev-secret", 1800L, 1209600L);
    }

    public AuthServerSecurityContextResolver(String jwtSecret, long accessTokenTtlSeconds, long refreshTokenTtlSeconds) {
        TokenService tokenService = new JwtTokenService(jwtSecret, accessTokenTtlSeconds, refreshTokenTtlSeconds);
        SessionStore sessionStore = new SimpleSessionStore();
        SessionPrincipalMapper mapper = new IdentitySessionPrincipalMapper();
        this.hybridAuthenticationProvider = new DefaultHybridAuthenticationProvider(
                tokenService,
                new DefaultSessionAuthenticationProvider(sessionStore, mapper)
        );
    }

    public AuthServerSecurityContextResolver(HybridAuthenticationProvider hybridAuthenticationProvider) {
        this.hybridAuthenticationProvider = Objects.requireNonNull(hybridAuthenticationProvider, "hybridAuthenticationProvider");
    }

    @Override
    public SecurityContext resolve(SecurityRequest request) {
        Objects.requireNonNull(request, "request");

        Map<String, String> attributes = request.attributes();
        Map<String, String> passthrough = new LinkedHashMap<>(attributes);

        Optional<Principal> authenticatedPrincipal = authenticate(attributes);
        if (authenticatedPrincipal.isPresent()) {
            passthrough.remove(ACCESS_TOKEN_ATTRIBUTE);
            passthrough.remove(SESSION_ID_ATTRIBUTE);
            return fromPrincipal(authenticatedPrincipal.get(), passthrough);
        }

        boolean authenticated = Boolean.parseBoolean(attributes.getOrDefault(AUTHENTICATED_ATTRIBUTE, "false"));
        String principal = trimToNull(attributes.get(PRINCIPAL_ATTRIBUTE));
        Set<String> roles = parseRoles(attributes.get(ROLES_ATTRIBUTE));

        passthrough.remove(AUTHENTICATED_ATTRIBUTE);
        passthrough.remove(PRINCIPAL_ATTRIBUTE);
        passthrough.remove(ROLES_ATTRIBUTE);
        passthrough.remove(ACCESS_TOKEN_ATTRIBUTE);
        passthrough.remove(SESSION_ID_ATTRIBUTE);

        return new SecurityContext(authenticated, principal, roles, passthrough);
    }

    private Optional<Principal> authenticate(Map<String, String> attributes) {
        String accessToken = trimToNull(attributes.get(ACCESS_TOKEN_ATTRIBUTE));
        String sessionId = trimToNull(attributes.get(SESSION_ID_ATTRIBUTE));
        if (accessToken == null && sessionId == null) {
            return Optional.empty();
        }
        return hybridAuthenticationProvider.authenticate(HybridAuthenticationContext.of(accessToken, sessionId));
    }

    private static SecurityContext fromPrincipal(Principal principal, Map<String, String> attributes) {
        Set<String> roles = principal.getAuthorities().stream()
                .map(AuthServerSecurityContextResolver::trimToNull)
                .filter(Objects::nonNull)
                .collect(Collectors.toUnmodifiableSet());

        Map<String, String> mergedAttributes = new LinkedHashMap<>(attributes);
        principal.getAttributes().forEach((key, value) -> {
            if (key != null && value != null) {
                mergedAttributes.putIfAbsent(key, String.valueOf(value));
            }
        });
        return new SecurityContext(true, principal.getUserId(), roles, mergedAttributes);
    }

    private static Set<String> parseRoles(String value) {
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        return java.util.Arrays.stream(value.split(","))
                .map(AuthServerSecurityContextResolver::trimToNull)
                .filter(Objects::nonNull)
                .collect(Collectors.toUnmodifiableSet());
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
