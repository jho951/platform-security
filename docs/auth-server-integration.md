# Auth-server Integration

`auth-server`는 3계층 서비스다.
OAuth2 login, user provisioning, cookie 정책, token/session 발급 비즈니스는 `auth-server`에 남긴다.
`platform-security`는 인증 결과를 표준 `SecurityContext`로 읽고, 공통 보안 파이프라인에 연결한다.

## 책임 분리

`auth-server` 책임:

- GitHub OAuth2 login 시작
- OAuth2 callback 처리
- provider user info 조회
- 사용자 provision / 상태 판단
- access token / refresh token / session 발급 비즈니스
- cookie / redirect 정책

`platform-security` 책임:

- JWT / session / hybrid credential 검증 capability 제공
- `SecurityContextResolver` 조립 지원
- OAuth2 결과 principal bridge 제공
- public route rate limit
- internal token claims validator hook
- IP guard / rate limit / downstream propagation

## Dependency

`auth-server`는 옛 auth starter를 직접 쓰지 않고, issuer 역할 starter를 사용한다.
internal API가 있어도 internal-service starter를 추가하지 않는다. auth-server의 주 역할은 issuer이고, internal API는 `boundary.internal-paths`로 분류한다.

```gradle
dependencies {
    implementation platform("io.github.jho951.platform:platform-security-bom:1.0.4")
    implementation "io.github.jho951.platform:platform-security-issuer-starter"
}
```

제거 대상:

```gradle
implementation "io.github.jho951:auth-spring"
implementation "io.github.jho951:auth-jwt-spring-boot-starter"
implementation "io.github.jho951:auth-hybrid-spring-boot-starter"
implementation "io.github.jho951:auth-starter"
implementation "io.github.jho951:ip-guard-spring-boot-starter"
```

OAuth2 client 자체는 `auth-server`의 로그인 flow이므로 유지한다.

```gradle
implementation "org.springframework.boot:spring-boot-starter-oauth2-client"
```

## SecurityContextResolver

`auth-server`는 실제 운영 `TokenService`와 Redis-backed session store를 `platform-security` resolver로 연결한다.

```java
@Configuration
class PlatformSecurityAuthConfig {

    @Bean
    @Primary
    SecurityContextResolver securityContextResolver(
            TokenService tokenService,
            SessionStore platformSecuritySessionStore,
            SessionPrincipalMapper sessionPrincipalMapper
    ) {
        return PlatformSecurityContextResolvers.hybrid(
                tokenService,
                platformSecuritySessionStore,
                sessionPrincipalMapper
        );
    }
}
```

`SessionStore`는 auth-server의 Redis/Sso session 저장소를 `com.auth.session.SessionStore`로 어댑팅한다.

```java
@Bean
SessionStore platformSecuritySessionStore(SsoSessionStore ssoSessionStore) {
    return new SessionStore() {
        @Override
        public void save(String sessionId, Principal principal) {
            // auth-server Redis session 저장소에 저장
        }

        @Override
        public Optional<Principal> find(String sessionId) {
            // Redis session을 Principal로 변환
        }

        @Override
        public void revoke(String sessionId) {
            // Redis session 폐기
        }
    };
}
```

## OAuth2 bridge

OAuth2 login flow는 auth-server가 수행한다.
2계층은 OAuth2 결과를 `Principal`로 표준화하는 bridge만 제공한다.

```java
@Bean
OAuth2PrincipalBridge oauth2PrincipalBridge(OAuth2PrincipalResolver resolver) {
    return PlatformSecurityContextResolvers.oauth2Bridge(resolver);
}
```

`OAuth2PrincipalResolver` 구현체 안에서는 서비스 비즈니스를 호출할 수 있다.
이 구현체는 auth-server 소유다.

```java
@Component
class AuthServerOAuth2PrincipalResolver implements OAuth2PrincipalResolver {
    private final SsoUserService ssoUserService;

    @Override
    public Principal resolve(OAuth2UserIdentity identity) {
        SsoPrincipal principal = ssoUserService.verifyOAuth2User(identity);
        return new Principal(principal.getUserId(), principal.getRoles());
    }
}
```

## OIDC API credential

auth-server가 OIDC ID token 자체를 API 인증 수단으로 받을 때만 `OidcTokenVerifier`를 제공한다.
기본 principal mapping은 2계층이 제공하므로 `OidcPrincipalMapper`는 서비스별 권한 매핑이 필요할 때만 override한다.

```java
@Bean
OidcTokenVerifier oidcTokenVerifier(AuthServerOidcVerifier verifier) {
    return request -> verifier.verify(request.idToken(), request.nonce());
}
```

```yaml
platform:
  security:
    auth:
      allow-oidc-for-api: true
      oidc:
        principal-claim: sub
        authorities-claim: roles
        default-authorities:
          - USER
```

일반 OAuth2 login callback 기반 로그인은 `OAuth2PrincipalBridge`를 우선 사용한다.

## Token / Session issuance

2계층은 발급 capability를 제공하지만, 로그인 성공 조건과 발급 시점은 auth-server가 결정한다.

```java
@Bean
TokenIssuanceCapability tokenIssuanceCapability(TokenService tokenService) {
    return PlatformSecurityContextResolvers.tokenIssuer(tokenService);
}

@Bean
SessionIssuanceCapability sessionIssuanceCapability(SessionStore sessionStore) {
    return PlatformSecurityContextResolvers.sessionIssuer(sessionStore);
}
```

Hybrid 발급이 필요하면:

```java
TokenIssuanceCapability issuer =
        PlatformSecurityContextResolvers.hybridIssuer(tokenService, sessionStore);
```

## Auth-server 권장 properties

```yaml
platform:
  security:
    boundary:
      public-paths:
        - /health
        - /auth/login
        - /auth/refresh
        - /auth/logout
        - /auth/sso/start
        - /auth/oauth2/authorize/**
        - /oauth2/**
        - /login/oauth2/**
      protected-paths:
        - /auth/session
        - /auth/me
      admin-paths:
        - /admin/**
      internal-paths:
        - /internal/**
        - /auth/internal/**

    auth:
      enabled: true
      default-mode: HYBRID
      allow-session-for-browser: true
      allow-bearer-for-api: true
      internal-token-enabled: true
      dev-fallback:
        enabled: false

    rate-limit:
      enabled: true
      anonymous:
        requests: 60
        window-seconds: 60
      authenticated:
        requests: 300
        window-seconds: 60
      internal:
        requests: 1000
        window-seconds: 60
      routes:
        - name: login
          patterns:
            - /auth/login
            - /v1/auth/login
          requests: 5
          window-seconds: 60
        - name: refresh
          patterns:
            - /auth/refresh
            - /v1/auth/refresh
          requests: 10
          window-seconds: 60
        - name: oauth2-start
          patterns:
            - /auth/sso/start
            - /v1/auth/sso/start
            - /auth/oauth2/authorize/**
            - /v1/auth/oauth2/authorize/**
          requests: 20
          window-seconds: 60
```

## 체크리스트

- `auth-server`가 `platform-security-issuer-starter`를 사용한다.
- 옛 auth starter 직접 의존을 제거했다.
- `spring-boot-starter-oauth2-client`는 유지한다.
- 운영 `SecurityContextResolver` bean을 제공한다.
- Redis-backed `SessionStore` adapter를 제공한다.
- `auth.dev-fallback.enabled=false`다.
- login/refresh/oauth2-start route rate limit을 설정했다.
- internal endpoint는 `internal-paths`에 포함했다.
- internal token audience/issuer 검증이 필요하면 `InternalTokenClaimsValidator`를 override한다.
