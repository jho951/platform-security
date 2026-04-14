# Configuration

`platform-security` 설정 prefix는 `platform.security`다.

이 문서는 설정 레퍼런스다. 적용 절차는 [quickstart.md](./quickstart.md)를 본다.

## 최상위 설정

| Property | 기본값 | 설명 |
| --- | --- | --- |
| `enabled` | `true` | platform-security 자동 구성을 켠다. |
| `service-role-preset` | `GENERAL` | 일반 starter를 쓸 때 역할 preset을 직접 지정한다. |
| `operational-policy.enabled` | `true` | 운영정책 검사를 켠다. |
| `operational-policy.production` | `false` | profile과 무관하게 운영정책 검사를 강제한다. |
| `operational-policy.production-profiles` | `prod,production,live` | 운영 profile 이름 목록이다. |

## 서비스 역할 preset

역할별 starter를 쓰면 preset이 자동 선택된다. 이 preset은 서비스의 주 역할(primary role)을 의미한다.

| Starter | Preset |
| --- | --- |
| `platform-security-edge-starter` | `EDGE` |
| `platform-security-issuer-starter` | `ISSUER` |
| `platform-security-resource-server-starter` | `RESOURCE_SERVER` |
| `platform-security-internal-service-starter` | `INTERNAL_SERVICE` |

일반 starter를 쓰는 경우:

```yaml
platform:
  security:
    service-role-preset: resource-server
```

Preset은 공통 boundary 골격과 auth mode 기본값만 제공한다. public path, route limit, 서비스별 boundary refinement는 3계층 설정이나 `PlatformSecurityCustomizer`가 제공한다.

서비스가 여러 endpoint 성격을 동시에 가져도 preset은 하나만 선택한다. 예를 들어 token/session issuer인 auth-server가 internal API도 제공하면 preset은 `ISSUER`로 두고, internal API는 `boundary.internal-paths`에 추가한다.

## Boundary

| Property | 기본값 | 설명 |
| --- | --- | --- |
| `boundary.public-paths` | `[]` | 인증 없이 접근 가능한 path pattern |
| `boundary.protected-paths` | `[]` | 일반 보호 path pattern |
| `boundary.admin-paths` | `[]` | admin path pattern |
| `boundary.internal-paths` | `[]` | internal path pattern |

기본 resolver는 설정값 외에도 다음 fallback pattern을 안다.

| Pattern | Boundary |
| --- | --- |
| `/health`, `/actuator/health` | `PUBLIC` |
| `/api`, `/api/**` | `PROTECTED` |
| `/admin`, `/admin/**` | `ADMIN` |
| `/internal`, `/internal/**` | `INTERNAL` |
| 그 외 | `PROTECTED` |

## Auth

| Property | 기본값 | 설명 |
| --- | --- | --- |
| `auth.enabled` | `true` | 인증 정책을 켠다. |
| `auth.default-mode` | `HYBRID` | credential이 명확하지 않을 때 기본 auth mode |
| `auth.allow-session-for-browser` | `true` | browser client의 session 허용 |
| `auth.allow-bearer-for-api` | `true` | API client의 bearer/JWT 허용 |
| `auth.allow-api-key-for-api` | `true` | API key credential 허용 |
| `auth.allow-hmac-for-api` | `true` | HMAC credential 허용 |
| `auth.allow-oidc-for-api` | `true` | OIDC ID token credential 허용 |
| `auth.service-account-enabled` | `true` | service account credential 허용 |
| `auth.internal-token-enabled` | `true` | internal token 허용 |
| `auth.dev-fallback.enabled` | `false` | local/test용 fallback resolver opt-in |
| `auth.jwt-secret` | dev default | 플랫폼 기본 `TokenService`가 쓸 JWT secret |
| `auth.access-token-ttl` | `30m` | access token TTL |
| `auth.refresh-token-ttl` | `14d` | refresh token TTL |

운영에서 `auth.enabled=true`이면 `SecurityContextResolver` bean이 반드시 필요하다.

## OIDC

OIDC token 검증은 2계층 책임이 아니다. 3계층이 `OidcTokenVerifier` bean을 제공하면 2계층이 capability를 연결한다.

| Property | 기본값 | 설명 |
| --- | --- | --- |
| `auth.oidc.principal-claim` | `sub` | principal claim |
| `auth.oidc.authorities-claim` | `roles` | authority claim |
| `auth.oidc.authority-prefix` | `""` | authority prefix |
| `auth.oidc.default-authorities` | `[]` | claim이 없을 때 기본 authority |

## IP Guard

| Property | 기본값 | 설명 |
| --- | --- | --- |
| `ip-guard.enabled` | `true` | IP guard를 켠다. |
| `ip-guard.trust-proxy` | `true` | proxy header 기반 client IP 해석을 허용한다. |
| `ip-guard.admin-allow-cidrs` | `[]` | admin boundary allow CIDR |
| `ip-guard.internal-allow-cidrs` | `[]` | internal boundary allow CIDR |

운영정책이 켜진 운영 환경에서는 admin/internal CIDR가 비어 있으면 기동 실패한다.

## Rate Limit

| Property | 기본값 | 설명 |
| --- | --- | --- |
| `rate-limit.enabled` | `true` | rate limit을 켠다. |
| `rate-limit.anonymous.requests` | `100` | anonymous quota |
| `rate-limit.anonymous.window-seconds` | `60` | anonymous window |
| `rate-limit.authenticated.requests` | `100` | authenticated quota |
| `rate-limit.authenticated.window-seconds` | `60` | authenticated window |
| `rate-limit.internal.requests` | `100` | internal quota |
| `rate-limit.internal.window-seconds` | `60` | internal window |
| `rate-limit.routes[].name` | `route` | route profile 이름 |
| `rate-limit.routes[].patterns` | `[]` | route path pattern |
| `rate-limit.routes[].requests` | `100` | route quota |
| `rate-limit.routes[].window-seconds` | `60` | route window |

Route profile은 boundary profile보다 먼저 선택된다. 따라서 `PUBLIC` endpoint도 `rate-limit.routes[]`에 매칭되면 rate limit이 적용된다.

예:

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

## 운영정책

운영정책은 다음 중 하나면 실행된다.

- active profile이 `prod`, `production`, `live`
- `platform.security.operational-policy.production=true`

운영정책 위반 조건:

- `auth.enabled=false`
- `auth.default-mode=NONE`
- `auth.dev-fallback.enabled=true`
- `SecurityContextResolver` bean 없음
- 플랫폼 기본 `TokenService`를 쓰면서 dev JWT secret 사용
- `ip-guard.enabled=false`
- `ip-guard.admin-allow-cidrs` 비어 있음
- `ip-guard.internal-allow-cidrs` 비어 있음
- `rate-limit.enabled=false`
- anonymous/authenticated/internal quota가 0 이하

## 최소 운영 예시

```yaml
spring:
  profiles:
    active: prod

platform:
  security:
    enabled: true

    boundary:
      public-paths:
        - /health
      protected-paths:
        - /api/**
      admin-paths:
        - /admin/**
      internal-paths:
        - /internal/**

    auth:
      enabled: true
      default-mode: HYBRID
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
```
