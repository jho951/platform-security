package io.github.jho951.platform.security.auth;

import com.auth.hybrid.DefaultHybridAuthenticationProvider;
import com.auth.hybrid.HybridAuthenticationProvider;
import com.auth.session.DefaultSessionAuthenticationProvider;
import com.auth.session.SessionPrincipalMapper;
import com.auth.session.SessionStore;
import com.auth.spi.OAuth2PrincipalResolver;
import com.auth.spi.TokenService;
import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityContextResolver;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.LinkedHashMap;
import java.util.Objects;
import java.util.Set;

/**
 * 공통 authentication resolver와 issuance capability를 만드는 factory다.
 *
 * <p>소비 서비스가 auth 1계층 OSS를 platform 흐름으로 연결하도록 돕는다. 단, 이
 * 클래스는 조립 helper일 뿐이다. 서비스별 로그인 성공 조건, OAuth2 provider flow,
 * 도메인 권한 판단은 소비 서비스에 남는다.</p>
 */
public final class PlatformSecurityContextResolvers {
    private PlatformSecurityContextResolvers() {
    }

    /**
     * request attributes를 유지하면서 항상 anonymous context를 반환하는 resolver를 만든다.
     *
     * @return anonymous context resolver
     */
    public static SecurityContextResolver anonymous() {
        return request -> {
            Objects.requireNonNull(request, "request");
            return new SecurityContext(false, null, Set.of(), new LinkedHashMap<>(request.attributes()));
        };
    }

    /**
     * auth 1계층 service로 JWT/session context resolver를 만든다.
     *
     * @param tokenService access token 검증을 담당하는 1계층 token service
     * @param sessionStore session 조회를 담당하는 1계층 session store
     * @param sessionPrincipalMapper session 값을 principal로 변환하는 mapper
     * @return JWT와 session을 모두 처리하는 context resolver
     */
    public static SecurityContextResolver hybrid(TokenService tokenService, SessionStore sessionStore, SessionPrincipalMapper sessionPrincipalMapper) {
        return from(hybridAuthenticationProvider(tokenService, sessionStore, sessionPrincipalMapper));
    }

    /**
     * 미리 구성된 hybrid provider로 context resolver를 만든다.
     *
     * @param hybridAuthenticationProvider 서비스가 구성한 hybrid provider
     * @return provider를 감싼 context resolver
     */
    public static SecurityContextResolver hybrid(HybridAuthenticationProvider hybridAuthenticationProvider) {
        return from(hybridAuthenticationProvider);
    }

    /**
     * hybrid provider를 JWT/session/hybrid 전용 platform authentication facade로 감싼다.
     *
     * @param hybridAuthenticationProvider 서비스가 구성한 hybrid provider
     * @return platform authentication facade
     */
    public static SecurityContextResolver from(HybridAuthenticationProvider hybridAuthenticationProvider) {
        Objects.requireNonNull(hybridAuthenticationProvider, "hybridAuthenticationProvider");
        PlatformSessionSupport platformSessionSupport = new DefaultPlatformSessionSupport(hybridAuthenticationProvider);
        return new PlatformAuthenticationFacade(new DefaultAuthenticationCapabilityResolver(
                new DefaultJwtAuthenticationCapability(platformSessionSupport),
                new DefaultSessionAuthenticationCapability(platformSessionSupport),
                new DefaultHybridAuthenticationCapability(platformSessionSupport),
                null
        ));
    }

    /**
     * hybrid provider와 internal claim validator를 platform authentication facade로 감싼다.
     *
     * @param hybridAuthenticationProvider 서비스가 구성한 hybrid provider
     * @param internalTokenClaimsValidator internal token claim 추가 검증 hook
     * @return internal capability까지 포함한 platform authentication facade
     */
    public static SecurityContextResolver from(
            HybridAuthenticationProvider hybridAuthenticationProvider,
            InternalTokenClaimsValidator internalTokenClaimsValidator
    ) {
        return new PlatformAuthenticationFacade(
                new DefaultPlatformSessionSupport(hybridAuthenticationProvider),
                internalTokenClaimsValidator
        );
    }

    /**
     * 서비스가 제공한 token/session infrastructure로 기본 hybrid provider 조합을 만든다.
     *
     * @param tokenService access token 검증을 담당하는 1계층 token service
     * @param sessionStore session 조회를 담당하는 1계층 session store
     * @param sessionPrincipalMapper session 값을 principal로 변환하는 mapper
     * @return 기본 hybrid authentication provider
     */
    public static HybridAuthenticationProvider hybridAuthenticationProvider(
            TokenService tokenService,
            SessionStore sessionStore,
            SessionPrincipalMapper sessionPrincipalMapper
    ) {
        Objects.requireNonNull(tokenService, "tokenService");
        Objects.requireNonNull(sessionStore, "sessionStore");
        Objects.requireNonNull(sessionPrincipalMapper, "sessionPrincipalMapper");
        return new DefaultHybridAuthenticationProvider(
                tokenService,
                new DefaultSessionAuthenticationProvider(sessionStore, sessionPrincipalMapper)
        );
    }

    /**
     * 서비스가 소유한 OAuth2 로그인 결과를 공통 principal 모델로 변환하는 bridge를 만든다.
     *
     * @param resolver auth 1계층 OAuth2 principal resolver
     * @return OAuth2 identity를 platform principal로 변환하는 bridge
     */
    public static OAuth2PrincipalBridge oauth2Bridge(OAuth2PrincipalResolver resolver) {
        return new DefaultOAuth2PrincipalBridge(resolver);
    }

    /**
     * 설정된 auth 1계층 token service에 위임하는 token issuer를 만든다.
     *
     * @param tokenService token 발급을 담당하는 1계층 token service
     * @return token issuance capability
     */
    public static TokenIssuanceCapability tokenIssuer(TokenService tokenService) {
        return new DefaultTokenIssuanceCapability(new TokenServicePlatformTokenIssuerPort(tokenService));
    }

    /**
     * 설정된 auth 1계층 session store에 위임하는 session issuer를 만든다.
     *
     * @param sessionStore session 저장을 담당하는 1계층 session store
     * @return session issuance capability
     */
    public static SessionIssuanceCapability sessionIssuer(SessionStore sessionStore) {
        return new DefaultSessionIssuanceCapability(new SessionStorePlatformSessionIssuerPort(sessionStore));
    }

    /**
     * access token, refresh token, session view를 함께 반환하는 issuer를 만든다.
     *
     * @param tokenService token 발급을 담당하는 1계층 token service
     * @param sessionStore session 저장을 담당하는 1계층 session store
     * @return token과 session을 함께 발급하는 capability
     */
    public static HybridIssuanceCapability hybridIssuer(TokenService tokenService, SessionStore sessionStore) {
        return new HybridIssuanceCapability(tokenIssuer(tokenService), sessionIssuer(sessionStore));
    }
}
