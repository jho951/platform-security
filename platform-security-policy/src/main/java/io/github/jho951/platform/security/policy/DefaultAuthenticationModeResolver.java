package io.github.jho951.platform.security.policy;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Locale;
import java.util.Objects;

public final class DefaultAuthenticationModeResolver implements AuthenticationModeResolver {
    private final PlatformSecurityProperties.AuthProperties authProperties;

    public DefaultAuthenticationModeResolver(PlatformSecurityProperties.AuthProperties authProperties) {
        this.authProperties = authProperties == null ? new PlatformSecurityProperties.AuthProperties() : authProperties;
    }

    @Override
    public AuthMode resolve(SecurityRequest request, SecurityContext context) {
        return resolve(request, context, null, null);
    }

    @Override
    public AuthMode resolve(SecurityRequest request, SecurityContext context, SecurityBoundary boundary, ClientType clientType) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(context, "context");
        String boundaryType = boundary == null ? normalize(request.attributes().get(SecurityAttributes.BOUNDARY)) : boundary.type().name();
        ClientType effectiveClientType = clientType == null ? resolveClientType(request) : clientType;
        if ("PUBLIC".equals(boundaryType)) {
            return AuthMode.NONE;
        }
        if (!authProperties.isEnabled() || authProperties.getDefaultMode() == AuthMode.NONE) {
            return AuthMode.NONE;
        }
        String sessionId = trimToNull(request.attributes().get("auth.sessionId"));
        String accessToken = trimToNull(request.attributes().get("auth.accessToken"));
        boolean authenticated = context.authenticated();

        if ("INTERNAL".equals(boundaryType)) {
            if (!authProperties.isInternalTokenEnabled()) {
                return authProperties.getDefaultMode();
            }
            if (authenticated) {
                return AuthMode.HYBRID;
            }
            if (accessToken != null && authProperties.isAllowBearerForApi()) {
                return AuthMode.JWT;
            }
            if (sessionId != null && authProperties.isAllowSessionForBrowser()) {
                return AuthMode.SESSION;
            }
            return authProperties.getDefaultMode();
        }

        if (effectiveClientType == ClientType.BROWSER) {
            if (sessionId != null && accessToken != null) {
                if (authProperties.isAllowSessionForBrowser() && authProperties.isAllowBearerForApi()) {
                    return AuthMode.HYBRID;
                }
                if (authProperties.isAllowSessionForBrowser()) {
                    return AuthMode.SESSION;
                }
                if (authProperties.isAllowBearerForApi()) {
                    return AuthMode.JWT;
                }
                return authProperties.getDefaultMode();
            }
            if (sessionId != null) {
                return authProperties.isAllowSessionForBrowser() ? AuthMode.SESSION : authProperties.getDefaultMode();
            }
            if (accessToken != null) {
                return authProperties.isAllowBearerForApi() ? AuthMode.JWT : authProperties.getDefaultMode();
            }
            return authProperties.getDefaultMode();
        }

        if (effectiveClientType == ClientType.EXTERNAL_API) {
            if (accessToken != null) {
                return authProperties.isAllowBearerForApi() ? AuthMode.JWT : authProperties.getDefaultMode();
            }
            if (sessionId != null) {
                return authProperties.isAllowSessionForBrowser() ? AuthMode.SESSION : authProperties.getDefaultMode();
            }
            return authProperties.getDefaultMode();
        }

        if (effectiveClientType == ClientType.INTERNAL_SERVICE) {
            return authenticated && authProperties.isInternalTokenEnabled()
                    ? AuthMode.HYBRID
                    : authProperties.getDefaultMode();
        }

        if (authenticated) {
            return authProperties.getDefaultMode();
        }
        if (sessionId != null && authProperties.isAllowSessionForBrowser()) {
            return AuthMode.SESSION;
        }
        if (accessToken != null && authProperties.isAllowBearerForApi()) {
            return AuthMode.JWT;
        }
        return authProperties.getDefaultMode();
    }

    private ClientType resolveClientType(SecurityRequest request) {
        String boundary = normalize(request.attributes().get(SecurityAttributes.BOUNDARY));
        if ("INTERNAL".equals(boundary)) {
            return ClientType.INTERNAL_SERVICE;
        }
        if ("ADMIN".equals(boundary)) {
            return ClientType.ADMIN_CONSOLE;
        }
        if (request.attributes().containsKey("auth.sessionId")) {
            return ClientType.BROWSER;
        }
        return ClientType.EXTERNAL_API;
    }

    private String normalize(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        return trimmed.toUpperCase(Locale.ROOT);
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
