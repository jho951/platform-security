package io.github.jho951.platform.security.auth;

import io.github.jho951.platform.security.policy.AuthMode;

import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

/**
 * {@link AuthMode}별 기본 capability lookup 구현이다.
 *
 * <p>2계층은 mode와 capability 연결만 담당한다. 각 credential의 검증, 저장소 조회,
 * provider별 정책은 capability 내부의 auth 1계층 provider로 위임한다.</p>
 */
public final class DefaultAuthenticationCapabilityResolver implements AuthenticationCapabilityResolver {
    private static final AuthenticationCapability NO_OP_CAPABILITY = new AuthenticationCapability() {
        @Override
        public String name() {
            return "none";
        }

        @Override
        public java.util.Optional<com.auth.api.model.Principal> authenticate(io.github.jho951.platform.security.api.SecurityRequest request) {
            return java.util.Optional.empty();
        }
    };

    private final Map<AuthMode, AuthenticationCapability> capabilities = new EnumMap<>(AuthMode.class);
    private final AuthenticationCapability internalCapability;

    /**
     * 기존 JWT/session/hybrid/internal mode만 사용하는 resolver를 만든다.
     *
     * @param jwtCapability JWT access token capability
     * @param sessionCapability session id capability
     * @param hybridCapability JWT와 session을 함께 처리하는 capability
     * @param internalCapability internal service token capability
     */
    public DefaultAuthenticationCapabilityResolver(
            AuthenticationCapability jwtCapability,
            AuthenticationCapability sessionCapability,
            AuthenticationCapability hybridCapability,
            AuthenticationCapability internalCapability
    ) {
        capabilities.put(AuthMode.JWT, capabilityOrNoop(jwtCapability));
        capabilities.put(AuthMode.SESSION, capabilityOrNoop(sessionCapability));
        capabilities.put(AuthMode.HYBRID, capabilityOrNoop(hybridCapability));
        capabilities.put(AuthMode.NONE, NO_OP_CAPABILITY);
        this.internalCapability = capabilityOrNoop(internalCapability);
    }

    /**
     * auth 3.0.1에서 추가된 API key, HMAC, OIDC, service account mode까지 포함한다.
     *
     * @param jwtCapability JWT access token capability
     * @param sessionCapability session id capability
     * @param hybridCapability JWT와 session을 함께 처리하는 capability
     * @param internalCapability internal service token capability
     * @param apiKeyCapability API key capability, 없으면 null 허용
     * @param hmacCapability HMAC signature capability, 없으면 null 허용
     * @param oidcCapability OIDC id_token capability, 없으면 null 허용
     * @param serviceAccountCapability service account capability, 없으면 null 허용
     */
    public DefaultAuthenticationCapabilityResolver(
            AuthenticationCapability jwtCapability,
            AuthenticationCapability sessionCapability,
            AuthenticationCapability hybridCapability,
            AuthenticationCapability internalCapability,
            AuthenticationCapability apiKeyCapability,
            AuthenticationCapability hmacCapability,
            AuthenticationCapability oidcCapability,
            AuthenticationCapability serviceAccountCapability
    ) {
        this(jwtCapability, sessionCapability, hybridCapability, internalCapability);
        putIfPresent(AuthMode.API_KEY, apiKeyCapability);
        putIfPresent(AuthMode.HMAC, hmacCapability);
        putIfPresent(AuthMode.OIDC, oidcCapability);
        putIfPresent(AuthMode.SERVICE_ACCOUNT, serviceAccountCapability);
    }

    @Override
    public AuthenticationCapability resolve(AuthMode authMode) {
        return capabilities.getOrDefault(authMode, capabilities.get(AuthMode.NONE));
    }

    @Override
    public AuthenticationCapability resolve(AuthMode authMode, boolean internalService) {
        if (internalService) {
            return internalCapability;
        }
        return resolve(authMode);
    }

    private void putIfPresent(AuthMode authMode, AuthenticationCapability capability) {
        if (capability != null) {
            capabilities.put(authMode, capability);
        }
    }

    private AuthenticationCapability capabilityOrNoop(AuthenticationCapability capability) {
        return capability == null ? NO_OP_CAPABILITY : Objects.requireNonNull(capability, "capability");
    }
}
