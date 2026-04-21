package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
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

/**
 * platform {@link SecurityRequest}를 auth 1계층 credential 검증으로 연결하는 facade다.
 *
 * <p>이 클래스는 request attributes에 담긴 credential key를 읽고, 결정된
 * {@link AuthMode}에 맞는 {@link AuthenticationCapability}를 호출한다. 로그인 flow,
 * OAuth2 provider 연동, 사용자 생성, 권한 정책은 소비 서비스 책임으로 남긴다.</p>
 */
public final class PlatformAuthenticationFacade implements SecurityContextResolver {
    /** 이미 인증된 context를 attributes로 직접 전달할 때 사용하는 flag key다. */
    public static final String AUTHENTICATED_ATTRIBUTE = "auth.authenticated";
    /** 이미 확인된 principal id를 attributes로 직접 전달할 때 사용하는 key다. */
    public static final String PRINCIPAL_ATTRIBUTE = "auth.principal";
    /** 이미 확인된 role 목록을 attributes로 직접 전달할 때 사용하는 key다. */
    public static final String ROLES_ATTRIBUTE = "auth.roles";
    /** bearer access token을 전달할 때 사용하는 key다. */
    public static final String ACCESS_TOKEN_ATTRIBUTE = "auth.accessToken";
    /** session id를 전달할 때 사용하는 key다. */
    public static final String SESSION_ID_ATTRIBUTE = "auth.sessionId";
    /** internal service token을 전달할 때 사용하는 key다. */
    public static final String INTERNAL_TOKEN_ATTRIBUTE = DefaultInternalServiceAuthenticationCapability.INTERNAL_TOKEN_ATTRIBUTE;
    /** API key id를 전달할 때 사용하는 key다. */
    public static final String API_KEY_ID_ATTRIBUTE = "auth.apiKeyId";
    /** API key secret을 전달할 때 사용하는 key다. */
    public static final String API_KEY_SECRET_ATTRIBUTE = "auth.apiKeySecret";
    /** HMAC key id를 전달할 때 사용하는 key다. */
    public static final String HMAC_KEY_ID_ATTRIBUTE = "auth.hmac.keyId";
    /** HMAC signature를 전달할 때 사용하는 key다. */
    public static final String HMAC_SIGNATURE_ATTRIBUTE = "auth.hmac.signature";
    /** HMAC timestamp를 전달할 때 사용하는 key다. */
    public static final String HMAC_TIMESTAMP_ATTRIBUTE = "auth.hmac.timestamp";
    /** HMAC 서명 대상 body를 전달할 때 사용하는 key다. */
    public static final String HMAC_BODY_ATTRIBUTE = "auth.hmac.body";
    /** OIDC id_token을 전달할 때 사용하는 key다. */
    public static final String OIDC_ID_TOKEN_ATTRIBUTE = "auth.oidc.idToken";
    /** OIDC nonce를 전달할 때 사용하는 key다. */
    public static final String OIDC_NONCE_ATTRIBUTE = "auth.oidc.nonce";
    /** service account id를 전달할 때 사용하는 key다. */
    public static final String SERVICE_ACCOUNT_ID_ATTRIBUTE = "auth.serviceAccountId";
    /** service account secret을 전달할 때 사용하는 key다. */
    public static final String SERVICE_ACCOUNT_SECRET_ATTRIBUTE = "auth.serviceAccountSecret";

    private final AuthenticationCapabilityResolver capabilityResolver;

    /**
     * 서비스가 구성한 capability resolver로 facade를 만든다.
     *
     * @param capabilityResolver auth mode를 capability로 연결하는 resolver
     */
    public PlatformAuthenticationFacade(AuthenticationCapabilityResolver capabilityResolver) {
        this.capabilityResolver = Objects.requireNonNull(capabilityResolver, "capabilityResolver");
    }

    /**
     * platform session support와 internal claim validator로 JWT/session/hybrid/internal capability를 구성한다.
     *
     * @param platformSessionSupport token/session 검증 port
     * @param internalTokenClaimsValidator internal token claim 추가 검증 hook
     */
    public PlatformAuthenticationFacade(
            PlatformSessionSupport platformSessionSupport,
            InternalTokenClaimsValidator internalTokenClaimsValidator
    ) {
        this(new DefaultAuthenticationCapabilityResolver(
                new DefaultJwtAuthenticationCapability(platformSessionSupport),
                new DefaultSessionAuthenticationCapability(platformSessionSupport),
                new DefaultHybridAuthenticationCapability(platformSessionSupport),
                new DefaultInternalServiceAuthenticationCapability(platformSessionSupport, internalTokenClaimsValidator)
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
            removeCredentialAttributes(attributes);
            return fromPrincipal(principal.get(), attributes);
        }

        boolean authenticated = Boolean.parseBoolean(attributes.getOrDefault(AUTHENTICATED_ATTRIBUTE, "false"));
        String subject = trimToNull(attributes.get(PRINCIPAL_ATTRIBUTE));
        Set<String> roles = parseRoles(attributes.get(ROLES_ATTRIBUTE));
        attributes.remove(AUTHENTICATED_ATTRIBUTE);
        attributes.remove(PRINCIPAL_ATTRIBUTE);
        attributes.remove(ROLES_ATTRIBUTE);
        removeCredentialAttributes(attributes);
        return new SecurityContext(authenticated, subject, roles, attributes);
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
        if (hasServiceAccountCredential(attributes)) {
            return AuthMode.SERVICE_ACCOUNT;
        }
        if (hasHmacCredential(attributes)) {
            return AuthMode.HMAC;
        }
        if (hasApiKeyCredential(attributes)) {
            return AuthMode.API_KEY;
        }
        if (trimToNull(attributes.get(OIDC_ID_TOKEN_ATTRIBUTE)) != null) {
            return AuthMode.OIDC;
        }
        if (trimToNull(attributes.get(INTERNAL_TOKEN_ATTRIBUTE)) != null) {
            return AuthMode.HYBRID;
        }
        return AuthMode.NONE;
    }

    private boolean isInternalService(Map<String, String> attributes, AuthMode authMode) {
        if (authMode == AuthMode.API_KEY
                || authMode == AuthMode.HMAC
                || authMode == AuthMode.OIDC
                || authMode == AuthMode.SERVICE_ACCOUNT) {
            return false;
        }
        String boundary = trimToNull(attributes.get(SecurityAttributes.BOUNDARY));
        if (boundary != null && "INTERNAL".equalsIgnoreCase(boundary)) {
            return true;
        }
        if (trimToNull(attributes.get(INTERNAL_TOKEN_ATTRIBUTE)) != null) {
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

    private boolean hasApiKeyCredential(Map<String, String> attributes) {
        return trimToNull(attributes.get(API_KEY_ID_ATTRIBUTE)) != null
                && trimToNull(attributes.get(API_KEY_SECRET_ATTRIBUTE)) != null;
    }

    private boolean hasHmacCredential(Map<String, String> attributes) {
        return trimToNull(attributes.get(HMAC_KEY_ID_ATTRIBUTE)) != null
                && trimToNull(attributes.get(HMAC_SIGNATURE_ATTRIBUTE)) != null;
    }

    private boolean hasServiceAccountCredential(Map<String, String> attributes) {
        return trimToNull(attributes.get(SERVICE_ACCOUNT_ID_ATTRIBUTE)) != null
                && trimToNull(attributes.get(SERVICE_ACCOUNT_SECRET_ATTRIBUTE)) != null;
    }

    private void removeCredentialAttributes(Map<String, String> attributes) {
        attributes.remove(ACCESS_TOKEN_ATTRIBUTE);
        attributes.remove(SESSION_ID_ATTRIBUTE);
        attributes.remove(INTERNAL_TOKEN_ATTRIBUTE);
        attributes.remove(API_KEY_ID_ATTRIBUTE);
        attributes.remove(API_KEY_SECRET_ATTRIBUTE);
        attributes.remove(HMAC_KEY_ID_ATTRIBUTE);
        attributes.remove(HMAC_SIGNATURE_ATTRIBUTE);
        attributes.remove(HMAC_TIMESTAMP_ATTRIBUTE);
        attributes.remove(HMAC_BODY_ATTRIBUTE);
        attributes.remove(OIDC_ID_TOKEN_ATTRIBUTE);
        attributes.remove(OIDC_NONCE_ATTRIBUTE);
        attributes.remove(SERVICE_ACCOUNT_ID_ATTRIBUTE);
        attributes.remove(SERVICE_ACCOUNT_SECRET_ATTRIBUTE);
        attributes.keySet().removeIf(key -> key != null && key.startsWith("auth.hmac.header."));
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
