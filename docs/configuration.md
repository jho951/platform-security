# Configuration

`platform-security`는 `platform.security.*` prefix로 설정한다.

## 기본 속성

- `enabled`
- `boundary.public-paths`
- `boundary.protected-paths`
- `boundary.admin-paths`
- `boundary.internal-paths`
- `auth.enabled`
- `auth.default-mode`
- `auth.allow-session-for-browser`
- `auth.allow-bearer-for-api`
- `auth.allow-api-key-for-api`
- `auth.allow-hmac-for-api`
- `auth.allow-oidc-for-api`
- `auth.service-account-enabled`
- `auth.internal-token-enabled`
- `auth.dev-fallback.enabled`
- `auth.jwt-secret`
- `auth.access-token-ttl`
- `auth.refresh-token-ttl`
- `ip-guard.enabled`
- `ip-guard.trust-proxy`
- `ip-guard.admin-allow-cidrs`
- `ip-guard.internal-allow-cidrs`
- `rate-limit.enabled`
- `rate-limit.anonymous.requests`
- `rate-limit.anonymous.window-seconds`
- `rate-limit.authenticated.requests`
- `rate-limit.authenticated.window-seconds`
- `rate-limit.internal.requests`
- `rate-limit.internal.window-seconds`
- `rate-limit.routes[].name`
- `rate-limit.routes[].patterns`
- `rate-limit.routes[].requests`
- `rate-limit.routes[].window-seconds`

## 설계 관점

- `boundary.*`는 요청 경계 분류 입력이다.
- `auth.*`는 인증 capability의 기본 정책이다.
- `ip-guard.*`는 boundary/profile에 따라 전달되는 IP 정책 입력이다.
- `rate-limit.*`는 profile이 선택한 quota 입력이다.
- `rate-limit.routes[]`는 PUBLIC boundary 안에서도 `/auth/login`, `/auth/refresh`, `/auth/sso/start` 같은 abuse-sensitive endpoint에 별도 quota를 적용한다.
- 서비스별 boundary pattern, trusted proxy, downstream 전달 규칙은 application이 공급한다.

## 기본 동작

- authentication은 기본 활성화
- IP guard는 기본 활성화
- rate limit은 기본 활성화
- auth가 활성화되어 있고 `SecurityContextResolver` bean이 없으면 시작 시 실패한다.
- dev fallback resolver는 기본 비활성화다.
- API key, HMAC, OIDC, service account는 1계층 resolver/verifier bean이 있을 때만 기본 capability로 연결된다.

## 운영 인증 resolver

운영 서비스는 `SecurityContextResolver`를 직접 등록해야 한다.
세션이나 hybrid 인증을 쓰는 서비스는 공유 `SessionStore`와 실제 `TokenService`를 조합한다.

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

local/test에서만 dev fallback을 명시적으로 켤 수 있다.

```yaml
platform:
  security:
    auth:
      dev-fallback:
        enabled: true
```

prod에서는 `dev-fallback.enabled=false`를 유지하고, 운영용 resolver bean을 반드시 제공한다.

## 설정 예시

## Route rate limit

`PUBLIC` boundary는 기본적으로 인증을 요구하지 않는다.
하지만 로그인, refresh, OAuth2 시작점은 공격 대상이므로 `rate-limit.routes[]`로 별도 quota를 둔다.

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
        - name: refresh
          patterns:
            - /auth/refresh
            - /v1/auth/refresh
          requests: 10
          window-seconds: 60
        - name: oauth2-start
          patterns:
            - /auth/sso/start
            - /auth/oauth2/authorize/**
          requests: 20
          window-seconds: 60
```

route profile은 boundary profile보다 먼저 선택된다.
따라서 `/auth/login`이 `PUBLIC`이어도 route profile에 매칭되면 rate limit이 적용된다.

### gateway-server

```yaml
platform:
  security:
    boundary:
      public-paths:
        - /health
        - /auth/login
        - /auth/refresh
      protected-paths:
        - /api/**
      admin-paths:
        - /admin/**
      internal-paths:
        - /internal/**

    auth:
      enabled: true
      default-mode: HYBRID
      allow-session-for-browser: true
      allow-bearer-for-api: true
      internal-token-enabled: true
      dev-fallback:
        enabled: false

    ip-guard:
      enabled: true
      trust-proxy: true
      admin-allow-cidrs:
        - 10.0.0.0/8
      internal-allow-cidrs:
        - 172.16.0.0/12

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
        - name: oauth2-start
          patterns:
            - /auth/sso/start
            - /auth/oauth2/authorize/**
            - /oauth2/**
          requests: 20
          window-seconds: 60
```

### auth-server

```yaml
platform:
  security:
    boundary:
      public-paths:
        - /health
        - /auth/login
        - /auth/refresh
        - /auth/logout
      protected-paths:
        - /api/**
      admin-paths:
        - /admin/**
      internal-paths:
        - /internal/**

    auth:
      enabled: true
      default-mode: HYBRID
      allow-session-for-browser: true
      allow-bearer-for-api: true
      internal-token-enabled: true
      dev-fallback:
        enabled: false

    ip-guard:
      enabled: true
      trust-proxy: true
      admin-allow-cidrs:
        - 10.0.0.0/8
      internal-allow-cidrs:
        - 172.16.0.0/12

    rate-limit:
      enabled: true
      anonymous:
        requests: 30
        window-seconds: 60
      authenticated:
        requests: 200
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

## 서비스별 해석

- `gateway-server`는 외부 진입점이라 public/auth/ip/rate-limit을 강하게 적용한다.
- `auth-server`는 로그인/토큰 갱신 엔드포인트를 public boundary로 둔다.
- 두 서비스 모두 같은 starter를 사용하고, properties와 override bean으로 차이를 흡수한다.
- auth-server는 `TokenService`와 Redis-backed session adapter를 이용해 `SecurityContextResolver`를 직접 제공한다.
- auth-server의 OAuth2 로그인 자체는 3계층 비즈니스에 남기고, 2계층은 OAuth2 결과 principal bridge와 token/session issuance capability만 제공한다.
