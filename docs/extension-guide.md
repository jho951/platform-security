# Extension Guide

## 추가 가능

- 새로운 boundary rule
- 새로운 security profile
- 새로운 auth policy / ip policy / rate-limit policy
- 새로운 identity propagation strategy
- 새로운 audit publisher
- 새로운 failure response writer
- 새로운 HTTP / Servlet adapter
- OAuth2 principal bridge
- token/session issuance capability
- internal token claims validator
- boundary/clientType/authMode profile-aware resolver/provider override
- `properties`, `customizer`, `override bean` 기반 확장

## 서비스가 공급하는 것

- boundary pattern
- profile 값
- trusted proxy 목록
- rate-limit key 전략
- downstream 전달 방식
- 운영용 `SecurityContextResolver`
- 운영용 `TokenService`, `SessionStore`, `SessionPrincipalMapper`

## 운영용 인증 확장

운영 서비스는 dev fallback을 사용하지 않고 `SecurityContextResolver`를 명시적으로 제공한다.

```java
@Bean
SecurityContextResolver securityContextResolver(
        TokenService tokenService,
        SessionStore sessionStore,
        SessionPrincipalMapper sessionPrincipalMapper
) {
    return PlatformSecurityContextResolvers.hybrid(tokenService, sessionStore, sessionPrincipalMapper);
}
```

JWT-only 서비스는 `SecurityContextResolver`를 직접 구현하거나, `AuthenticationCapabilityResolver`를 mode별로 교체한다.
세션/HYBRID 서비스는 공유 세션 저장소를 `com.auth.session.SessionStore`로 어댑팅한다.

## 주요 override point

- `SecurityContextResolver`
- `SecurityBoundaryResolver`
- `ClientTypeResolver`
- `AuthenticationModeResolver`
- `ClientIpResolver`
- `BoundaryIpPolicyProvider`
- `BoundaryRateLimitPolicyProvider`
- `RateLimitKeyResolver`
- `PlatformPrincipalFactory`
- `PlatformSecurityCustomizer`
- `OAuth2PrincipalBridge`
- `TokenIssuanceCapability`
- `SessionIssuanceCapability`
- `InternalTokenClaimsValidator`
- `SecurityDownstreamIdentityPropagator`
- `SecurityAuditPublisher`
- `ApiKeyPrincipalResolver`
- `HmacSecretResolver`
- `HmacSignatureVerifier`
- `HmacPrincipalResolver`
- `OidcTokenVerifier`
- `OidcPrincipalMapper`
- `ServiceAccountVerifier`

## Auth 3.0.1 capability

API key, HMAC, OIDC, service account 인증은 1계층 auth provider를 감싸는 capability로 제공한다.
2계층은 credential 위치, mode 선택, provider 조립, 기본 OIDC principal mapping만 표준화한다.
실제 key 조회, signature 검증, ID token 검증, service account 검증은 1계층 구현 또는 3계층 서비스가 bean으로 공급한다.

OIDC를 API 인증 수단으로 소비하는 3계층은 최소 `OidcTokenVerifier`만 제공하면 된다.
`OidcPrincipalMapper`는 기본 bean이 등록되며, 도메인 권한/tenant 매핑이 필요할 때만 override한다.

```java
@Bean
OidcTokenVerifier oidcTokenVerifier(ServiceOidcVerifier verifier) {
    return request -> verifier.verify(request.idToken(), request.nonce());
}
```

## OAuth2 bridge

OAuth2 login flow는 3계층 서비스가 가진다.
2계층은 OAuth2 결과를 표준 auth principal로 변환하는 bridge만 제공한다.

```java
@Bean
OAuth2PrincipalBridge oauth2PrincipalBridge(OAuth2PrincipalResolver resolver) {
    return PlatformSecurityContextResolvers.oauth2Bridge(resolver);
}
```

GitHub token exchange, user provisioning, redirect, cookie 발급은 `auth-server` 책임이다.

## Token / Session issuance

2계층은 1계층 `TokenService`와 `SessionStore`를 조합하는 capability를 제공한다.

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

로그인 성공 조건, 계정 상태 판단, refresh rotation 같은 비즈니스는 서비스가 담당한다.

## Internal token 검증

내부 서비스 토큰의 audience, issuer, service-id 같은 조직별 검증은 `InternalTokenClaimsValidator`로 교체한다.

```java
@Bean
InternalTokenClaimsValidator internalTokenClaimsValidator() {
    return (principal, request) -> "billing-service".equals(principal.getAttribute("aud"));
}
```

## Route rate limit

PUBLIC boundary라도 로그인, refresh, OAuth2 시작점은 route profile로 별도 제한한다.

```yaml
platform:
  security:
    rate-limit:
      routes:
        - name: login
          patterns:
            - /auth/login
            - /v1/auth/login
          requests: 5
          window-seconds: 60
```

## 추가 순서

1. 내부 공통 계약과 공통 모델이 필요하면 `platform-security-policy`에 먼저 추가한다.
2. capability 조립이 필요하면 `platform-security-auth`, `platform-security-ip`, `platform-security-rate-limit`에 넣는다.
3. HTTP / Servlet 적응이 필요하면 `platform-security-web`에 넣는다.
4. Spring 노출이 필요하면 `platform-security-autoconfigure`에서 조건부 빈으로 등록한다.
5. `docs/security-model.md`와 `docs/modules.md`를 함께 갱신한다.

## 주의점

- policy와 capability 모듈에 Spring 의존성을 넣지 않는다.
- engine은 Servlet / Spring 타입을 몰라야 한다.
- policy는 결정 이유를 설명할 수 있어야 한다.
- rate limit은 시간 의존성을 주입 가능하게 유지한다.
- provider는 boundary만 보지 말고 profile-aware overload를 제공할 수 있어야 한다.
- 서비스별 URL, Redis key, role 이름은 추가하지 않는다.
- 1계층 OSS의 내부 구현을 여기서 다시 정의하지 않는다.
- 2계층은 공개 라이브러리보다 내부 플랫폼이라는 기준으로 설계한다.
- 서비스별 비즈니스 로직과 도메인 권한 판단은 추가하지 않는다.
- dev fallback resolver를 운영 기본값으로 쓰지 않는다.
- `SecurityContextResolver`를 등록하지 않은 운영 서비스가 뜨도록 만들지 않는다.
