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
import io.github.jho951.platform.security.api.SecurityContextResolver;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.policy.AuthMode;
import io.github.jho951.platform.security.policy.SecurityAttributes;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public final class PlatformAuthenticationFacade implements SecurityContextResolver {
    public static final String AUTHENTICATED_ATTRIBUTE = "auth.authenticated";
    public static final String PRINCIPAL_ATTRIBUTE = "auth.principal";
    public static final String ROLES_ATTRIBUTE = "auth.roles";
    public static final String ACCESS_TOKEN_ATTRIBUTE = "auth.accessToken";
    public static final String SESSION_ID_ATTRIBUTE = "auth.sessionId";
    public static final String INTERNAL_TOKEN_ATTRIBUTE = DefaultInternalServiceAuthenticationCapability.INTERNAL_TOKEN_ATTRIBUTE;

    private final AuthenticationCapabilityResolver capabilityResolver;

    public PlatformAuthenticationFacade() {
        this("platform-security-dev-secret-platform-security-dev-secret", 1800L, 1209600L);
    }

    public PlatformAuthenticationFacade(String jwtSecret, long accessTokenTtlSeconds, long refreshTokenTtlSeconds) {
        this(createDefaultResolver(jwtSecret, accessTokenTtlSeconds, refreshTokenTtlSeconds));
    }

    public PlatformAuthenticationFacade(AuthenticationCapabilityResolver capabilityResolver) {
        this.capabilityResolver = Objects.requireNonNull(capabilityResolver, "capabilityResolver");
    }

    public PlatformAuthenticationFacade(HybridAuthenticationProvider hybridAuthenticationProvider) {
        this(new DefaultAuthenticationCapabilityResolver(
                new DefaultJwtAuthenticationCapability(hybridAuthenticationProvider),
                new DefaultSessionAuthenticationCapability(hybridAuthenticationProvider),
                new DefaultHybridAuthenticationCapability(hybridAuthenticationProvider),
                new DefaultInternalServiceAuthenticationCapability(hybridAuthenticationProvider)
        ));
    }

    @Override
    public SecurityContext resolve(SecurityRequest request) {
        Objects.requireNonNull(request, "request");
        var attributes = new LinkedHashMap<>(request.attributes());
        AuthMode authMode = resolveAuthMode(attributes);
        boolean internalService = isInternalService(attributes, authMode);
        Optional<Principal> principal = capabilityResolver.resolve(authMode, internalService).authenticate(request);
        if (principal.isPresent()) {
            attributes.remove(ACCESS_TOKEN_ATTRIBUTE);
            attributes.remove(SESSION_ID_ATTRIBUTE);
            attributes.remove(INTERNAL_TOKEN_ATTRIBUTE);
            return fromPrincipal(principal.get(), attributes);
        }

        boolean authenticated = Boolean.parseBoolean(attributes.getOrDefault(AUTHENTICATED_ATTRIBUTE, "false"));
        String subject = trimToNull(attributes.get(PRINCIPAL_ATTRIBUTE));
        Set<String> roles = parseRoles(attributes.get(ROLES_ATTRIBUTE));
        attributes.remove(AUTHENTICATED_ATTRIBUTE);
        attributes.remove(PRINCIPAL_ATTRIBUTE);
        attributes.remove(ROLES_ATTRIBUTE);
        attributes.remove(ACCESS_TOKEN_ATTRIBUTE);
        attributes.remove(SESSION_ID_ATTRIBUTE);
        attributes.remove(INTERNAL_TOKEN_ATTRIBUTE);
        return new SecurityContext(authenticated, subject, roles, attributes);
    }

    private static AuthenticationCapabilityResolver createDefaultResolver(
            String jwtSecret,
            long accessTokenTtlSeconds,
            long refreshTokenTtlSeconds
    ) {
        TokenService tokenService = new JwtTokenService(jwtSecret, accessTokenTtlSeconds, refreshTokenTtlSeconds);
        SessionStore sessionStore = new SimpleSessionStore();
        SessionPrincipalMapper mapper = new IdentitySessionPrincipalMapper();
        HybridAuthenticationProvider hybridAuthenticationProvider = new DefaultHybridAuthenticationProvider(
                tokenService,
                new DefaultSessionAuthenticationProvider(sessionStore, mapper)
        );
        return new DefaultAuthenticationCapabilityResolver(
                new DefaultJwtAuthenticationCapability(hybridAuthenticationProvider),
                new DefaultSessionAuthenticationCapability(hybridAuthenticationProvider),
                new DefaultHybridAuthenticationCapability(hybridAuthenticationProvider),
                new DefaultInternalServiceAuthenticationCapability(hybridAuthenticationProvider)
        );
    }

    private AuthMode resolveAuthMode(Map<String, String> attributes) {
        String explicit = trimToNull(attributes.get(SecurityAttributes.AUTH_MODE));
        if (explicit != null) {
            try {
                return AuthMode.valueOf(explicit.trim().toUpperCase(java.util.Locale.ROOT));
            } catch (IllegalArgumentException ignored) {
                // fall through to inference
            }
        }

        String accessToken = trimToNull(attributes.get(ACCESS_TOKEN_ATTRIBUTE));
        String sessionId = trimToNull(attributes.get(SESSION_ID_ATTRIBUTE));
        if (accessToken != null && sessionId != null) {
            return AuthMode.HYBRID;
        }
        if (sessionId != null) {
            return AuthMode.SESSION;
        }
        if (accessToken != null) {
            return AuthMode.JWT;
        }
        if (Boolean.parseBoolean(attributes.getOrDefault(INTERNAL_TOKEN_ATTRIBUTE, "false"))) {
            return AuthMode.HYBRID;
        }
        return AuthMode.NONE;
    }

    private boolean isInternalService(Map<String, String> attributes, AuthMode authMode) {
        String boundary = trimToNull(attributes.get(SecurityAttributes.BOUNDARY));
        if (boundary != null && "INTERNAL".equalsIgnoreCase(boundary)) {
            return true;
        }
        if (Boolean.parseBoolean(attributes.getOrDefault(INTERNAL_TOKEN_ATTRIBUTE, "false"))) {
            return true;
        }
        return authMode == AuthMode.HYBRID && "true".equalsIgnoreCase(attributes.getOrDefault("auth.internal", "false"));
    }

    private static SecurityContext fromPrincipal(Principal principal, java.util.Map<String, String> attributes) {
        Set<String> roles = principal.getAuthorities().stream()
                .map(PlatformAuthenticationFacade::trimToNull)
                .filter(Objects::nonNull)
                .collect(Collectors.toUnmodifiableSet());

        var merged = new LinkedHashMap<>(attributes);
        principal.getAttributes().forEach((key, value) -> {
            if (key != null && value != null) {
                merged.putIfAbsent(key, String.valueOf(value));
            }
        });
        return new SecurityContext(true, principal.getUserId(), roles, merged);
    }

    private static Set<String> parseRoles(String value) {
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        return java.util.Arrays.stream(value.split(","))
                .map(PlatformAuthenticationFacade::trimToNull)
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
