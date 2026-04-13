package io.github.jho951.platform.security.auth;

import com.auth.hybrid.DefaultHybridAuthenticationProvider;
import com.auth.hybrid.HybridAuthenticationProvider;
import com.auth.session.DefaultSessionAuthenticationProvider;
import com.auth.session.IdentitySessionPrincipalMapper;
import com.auth.session.SessionPrincipalMapper;
import com.auth.session.SessionStore;
import com.auth.session.SimpleSessionStore;
import com.auth.spi.OAuth2PrincipalResolver;
import com.auth.spi.TokenService;
import com.auth.support.jwt.JwtTokenService;
import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityContextResolver;
import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.LinkedHashMap;
import java.util.Objects;
import java.util.Set;

/**
 * 공통 authentication resolver와 issuance capability를 만드는 factory다.
 *
 * <p>소비 서비스가 auth 1계층 provider를 직접 조립하지 않도록 돕는다. 단, 이
 * 클래스는 조립 helper일 뿐이다. 서비스별 로그인 성공 조건, OAuth2 provider flow,
 * 도메인 권한 판단은 소비 서비스에 남는다.</p>
 */
public final class PlatformSecurityContextResolvers {
    private PlatformSecurityContextResolvers() {
    }

    /**
     * local/dev fallback facade를 반환한다.
     *
     * <p>운영에서는 서비스가 구성한 token service, session store, provider를 명시적으로
     * 주입해야 한다.</p>
     *
     * @return local/dev fallback security context resolver
     */
    public static SecurityContextResolver devFallback() {
        return new PlatformAuthenticationFacade();
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
     * auth 1계층 service로 hybrid JWT/session context resolver를 만든다.
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
     * hybrid provider를 platform authentication facade로 감싼다.
     *
     * @param hybridAuthenticationProvider 서비스가 구성한 hybrid provider
     * @return platform authentication facade
     */
    public static SecurityContextResolver from(HybridAuthenticationProvider hybridAuthenticationProvider) {
        return new PlatformAuthenticationFacade(hybridAuthenticationProvider);
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
     * in-memory session storage를 쓰는 local fallback hybrid provider를 만든다.
     * local/test 경로에서만 사용한다.
     *
     * @param jwtSecret local fallback JWT secret
     * @param accessTokenTtlSeconds access token TTL 초 단위
     * @param refreshTokenTtlSeconds refresh token TTL 초 단위
     * @return local/test 용도 hybrid provider
     */
    public static HybridAuthenticationProvider defaultHybridAuthenticationProvider(String jwtSecret, long accessTokenTtlSeconds, long refreshTokenTtlSeconds) {
        Objects.requireNonNull(jwtSecret, "jwtSecret");
        TokenService tokenService = new JwtTokenService(jwtSecret, accessTokenTtlSeconds, refreshTokenTtlSeconds);
        SessionStore sessionStore = new SimpleSessionStore();
        SessionPrincipalMapper sessionPrincipalMapper = new IdentitySessionPrincipalMapper();
        return hybridAuthenticationProvider(tokenService, sessionStore, sessionPrincipalMapper);
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
        return new DefaultTokenIssuanceCapability(tokenService);
    }

    /**
     * 설정된 auth 1계층 session store에 위임하는 session issuer를 만든다.
     *
     * @param sessionStore session 저장을 담당하는 1계층 session store
     * @return session issuance capability
     */
    public static SessionIssuanceCapability sessionIssuer(SessionStore sessionStore) {
        return new DefaultSessionIssuanceCapability(sessionStore);
    }

    /**
     * access token, refresh token, session id를 함께 반환하는 issuer를 만든다.
     *
     * @param tokenService token 발급을 담당하는 1계층 token service
     * @param sessionStore session 저장을 담당하는 1계층 session store
     * @return token과 session을 함께 발급하는 capability
     */
    public static TokenIssuanceCapability hybridIssuer(TokenService tokenService, SessionStore sessionStore) {
        return new HybridIssuanceCapability(tokenIssuer(tokenService), sessionIssuer(sessionStore));
    }
}
