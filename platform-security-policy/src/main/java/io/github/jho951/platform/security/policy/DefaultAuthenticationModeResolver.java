package io.github.jho951.platform.security.policy;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Locale;
import java.util.Objects;

/**
 * platform-security 기본 인증 방식 resolver다.
 *
 * <p>boundary가 PUBLIC이면 인증을 생략하고, credential attribute가 명확하면 해당
 * capability를 우선 선택한다. credential이 없으면 client type과 auth 설정의 기본 mode를
 * 사용한다.</p>
 */
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
        AuthMode credentialMode = resolveCredentialMode(request);
        if (credentialMode != null) {
            return credentialMode;
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

    private AuthMode resolveCredentialMode(SecurityRequest request) {
        if (hasServiceAccountCredential(request) && authProperties.isServiceAccountEnabled()) {
            return AuthMode.SERVICE_ACCOUNT;
        }
        if (hasHmacCredential(request) && authProperties.isAllowHmacForApi()) {
            return AuthMode.HMAC;
        }
        if (hasApiKeyCredential(request) && authProperties.isAllowApiKeyForApi()) {
            return AuthMode.API_KEY;
        }
        if (hasOidcCredential(request) && authProperties.isAllowOidcForApi()) {
            return AuthMode.OIDC;
        }
        return null;
    }

    private boolean hasApiKeyCredential(SecurityRequest request) {
        return trimToNull(request.attributes().get("auth.apiKeyId")) != null
                && trimToNull(request.attributes().get("auth.apiKeySecret")) != null;
    }

    private boolean hasHmacCredential(SecurityRequest request) {
        return trimToNull(request.attributes().get("auth.hmac.keyId")) != null
                && trimToNull(request.attributes().get("auth.hmac.signature")) != null;
    }

    private boolean hasOidcCredential(SecurityRequest request) {
        return trimToNull(request.attributes().get("auth.oidc.idToken")) != null;
    }

    private boolean hasServiceAccountCredential(SecurityRequest request) {
        return trimToNull(request.attributes().get("auth.serviceAccountId")) != null
                && trimToNull(request.attributes().get("auth.serviceAccountSecret")) != null;
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
