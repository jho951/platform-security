package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.hybrid.HybridAuthenticationContext;
import com.auth.hybrid.HybridAuthenticationProvider;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * 내부 서비스 간 호출에 사용하는 internal token capability다.
 *
 * <p>token 검증은 1계층 hybrid provider가 맡고, 서비스별 issuer/audience/service id
 * 검증은 {@link InternalTokenClaimsValidator} hook으로 분리한다.</p>
 */
public final class DefaultInternalServiceAuthenticationCapability implements AuthenticationCapability {
    /** request attributes에서 internal token을 읽을 때 사용하는 key다. */
    public static final String INTERNAL_TOKEN_ATTRIBUTE = "auth.internalToken";

    private final HybridAuthenticationProvider hybridAuthenticationProvider;
    private final InternalTokenClaimsValidator claimsValidator;

    /**
     * claim 추가 검증 없이 internal token capability를 만든다.
     *
     * @param hybridAuthenticationProvider token/session 검증 provider
     */
    public DefaultInternalServiceAuthenticationCapability(HybridAuthenticationProvider hybridAuthenticationProvider) {
        this(hybridAuthenticationProvider, InternalTokenClaimsValidator.allowAll());
    }

    /**
     * service-specific claim validator를 포함한 internal token capability를 만든다.
     *
     * @param hybridAuthenticationProvider token/session 검증 provider
     * @param claimsValidator internal token claim 추가 검증 hook
     */
    public DefaultInternalServiceAuthenticationCapability(
            HybridAuthenticationProvider hybridAuthenticationProvider,
            InternalTokenClaimsValidator claimsValidator
    ) {
        this.hybridAuthenticationProvider = Objects.requireNonNull(hybridAuthenticationProvider, "hybridAuthenticationProvider");
        this.claimsValidator = Objects.requireNonNull(claimsValidator, "claimsValidator");
    }

    @Override
    public String name() {
        return "internal";
    }

    @Override
    public Optional<Principal> authenticate(SecurityRequest request) {
        return doAuthenticate(request);
    }

    Optional<Principal> doAuthenticate(SecurityRequest request) {
        Map<String, String> attributes = request.attributes();
        String internalToken = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(INTERNAL_TOKEN_ATTRIBUTE));
        String sessionId = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.SESSION_ID_ATTRIBUTE));
        if (internalToken == null && sessionId == null) {
            return Optional.empty();
        }
        Principal principal = hybridAuthenticationProvider.authenticate(HybridAuthenticationContext.of(internalToken, sessionId)).orElse(null);
        if (principal != null && !claimsValidator.validate(principal, request)) {
            return Optional.empty();
        }
        return Optional.ofNullable(principal);
    }
}
