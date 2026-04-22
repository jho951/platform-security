package io.github.jho951.platform.security.auth;

import com.auth.oidc.OidcAuthenticationProvider;
import com.auth.oidc.OidcAuthenticationRequest;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * OIDC id_token credential을 처리하는 platform authentication capability다.
 *
 * <p>{@link SecurityRequest#attributes()}에서 {@code auth.oidc.idToken}과
 * {@code auth.oidc.nonce}를 꺼내 auth 1계층의 {@link OidcAuthenticationProvider}에
 * 위임한다. 검증 실패는 empty result로 바꿔 platform policy 계층이 일반 인증 실패
 * 응답을 만들 수 있게 한다.</p>
 */
public final class DefaultOidcAuthenticationCapability implements AuthenticationCapability {
    private final OidcAuthenticationProvider oidcAuthenticationProvider;

    /**
     * OIDC id_token 검증을 수행할 1계층 provider와 capability를 연결한다.
     *
     * @param oidcAuthenticationProvider id_token 검증과 principal 생성을 담당하는 provider
     */
    public DefaultOidcAuthenticationCapability(OidcAuthenticationProvider oidcAuthenticationProvider) {
        this.oidcAuthenticationProvider = Objects.requireNonNull(oidcAuthenticationProvider, "oidcAuthenticationProvider");
    }

    @Override
    public String name() {
        return "oidc";
    }

    @Override
    public Optional<PlatformAuthenticatedPrincipal> authenticate(SecurityRequest request) {
        Map<String, String> attributes = request.attributes();
        String idToken = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.OIDC_ID_TOKEN_ATTRIBUTE));
        if (idToken == null) {
            return Optional.empty();
        }
        String nonce = DefaultJwtAuthenticationCapability.trimToNull(attributes.get(PlatformAuthenticationFacade.OIDC_NONCE_ATTRIBUTE));
        try {
            return oidcAuthenticationProvider.authenticate(new OidcAuthenticationRequest(idToken, nonce))
                    .map(AuthPrincipalAdapters::toPlatform);
        } catch (RuntimeException ex) {
            return Optional.empty();
        }
    }
}
