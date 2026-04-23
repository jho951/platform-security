package io.github.jho951.platform.security.auth;

import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Map;
import java.util.Optional;

/**
 * 내부 서비스 간 호출에 사용하는 internal token capability다.
 *
 * <p>token 검증은 platform session support port가 맡고, 서비스별 issuer/audience/service id
 * 검증은 {@link InternalTokenClaimsValidator} hook으로 분리한다.</p>
 */
public final class DefaultInternalServiceAuthenticationCapability implements AuthenticationCapability {
    /** request attributes에서 internal token을 읽을 때 사용하는 key다. */
    public static final String INTERNAL_TOKEN_ATTRIBUTE = "auth.internalToken";
    /** request attributes에서 legacy internal request secret을 읽을 때 사용하는 key다. */
    public static final String INTERNAL_REQUEST_SECRET_ATTRIBUTE = "auth.internalRequestSecret";

    private final PlatformSessionSupport platformSessionSupport;
    private final InternalTokenClaimsValidator claimsValidator;
    private final java.util.List<InternalServiceCompatibilityAuthenticationAdapter> compatibilityAdapters;

    /**
     * service-specific claim validator를 포함한 internal token capability를 만든다.
     *
     * @param platformSessionSupport token/session 검증 port
     * @param claimsValidator internal token claim 추가 검증 hook
     */
    public DefaultInternalServiceAuthenticationCapability(
            PlatformSessionSupport platformSessionSupport,
            InternalTokenClaimsValidator claimsValidator
    ) {
        this(platformSessionSupport, claimsValidator, java.util.List.of());
    }

    /**
     * internal token 검증과 compatibility adapter fallback을 함께 포함한 capability를 만든다.
     *
     * @param platformSessionSupport token/session 검증 port, 없으면 null 허용
     * @param claimsValidator internal token claim 추가 검증 hook, 없으면 null 허용
     * @param compatibilityAdapters legacy compatibility fallback 목록
     */
    public DefaultInternalServiceAuthenticationCapability(
            PlatformSessionSupport platformSessionSupport,
            InternalTokenClaimsValidator claimsValidator,
            java.util.List<InternalServiceCompatibilityAuthenticationAdapter> compatibilityAdapters
    ) {
        this.platformSessionSupport = platformSessionSupport;
        this.claimsValidator = claimsValidator;
        this.compatibilityAdapters = compatibilityAdapters == null ? java.util.List.of() : java.util.List.copyOf(compatibilityAdapters);
    }

    @Override
    public String name() {
        return "internal";
    }

    @Override
    public Optional<PlatformAuthenticatedPrincipal> authenticate(SecurityRequest request) {
        return doAuthenticate(request);
    }

    Optional<PlatformAuthenticatedPrincipal> doAuthenticate(SecurityRequest request) {
        Map<String, String> attributes = request.attributes();
        String internalToken = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(INTERNAL_TOKEN_ATTRIBUTE));
        if (internalToken == null) {
            internalToken = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.ACCESS_TOKEN_ATTRIBUTE));
        }
        String sessionId = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.SESSION_ID_ATTRIBUTE));
        Optional<PlatformAuthenticatedPrincipal> tokenPrincipal = authenticateTokenOrSession(internalToken, sessionId, request);
        if (tokenPrincipal.isPresent()) {
            return tokenPrincipal;
        }

        for (InternalServiceCompatibilityAuthenticationAdapter compatibilityAdapter : compatibilityAdapters) {
            Optional<PlatformAuthenticatedPrincipal> compatibilityPrincipal = compatibilityAdapter.authenticate(request);
            if (compatibilityPrincipal.isPresent()) {
                return compatibilityPrincipal;
            }
        }
        return Optional.empty();
    }

    private Optional<PlatformAuthenticatedPrincipal> authenticateTokenOrSession(
            String internalToken,
            String sessionId,
            SecurityRequest request
    ) {
        if (platformSessionSupport == null || internalToken == null && sessionId == null) {
            return Optional.empty();
        }

        PlatformAuthenticatedPrincipal principal = platformSessionSupport.authenticate(internalToken, sessionId).orElse(null);
        if (principal == null) {
            return Optional.empty();
        }
        if (claimsValidator != null && !claimsValidator.validate(principal, request)) {
            return Optional.empty();
        }
        return Optional.of(principal);
    }
}
