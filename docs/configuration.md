# Configuration

## 기본 설정

이 설정은 3계층 서비스의 `application.yml`에 넣는다.  
`platform-security`를 사용할지, 그리고 운영 안전검사를 언제 적용할지 정한다.

| 설정 | 기본값 | 쉬운 설명 |
| --- | --- | --- |
| `enabled` | `true` | 이 서비스에서 `platform-security`를 사용할지 정한다. |
| `service-role-preset` | `GENERAL` | 이 서비스를 edge/issuer/api-server/internal-service 중 무엇으로 볼지 정한다. |
| `operational.enabled` | `true` | 위험한 운영 설정을 애플리케이션 시작 시점에 막는 검사를 켠다. 기존 `operational-policy.enabled`도 계속 동작한다. |
| `operational.production` | `false` | 현재 Spring profile과 상관없이 이 서비스를 운영처럼 검사한다. CI나 staging에서 운영 수준 검사를 강제로 걸 때 쓴다. 기존 `operational-policy.production`도 계속 동작한다. |
| `operational.production-profiles` | `prod`, `production` | 이 Spring profile로 뜨면 운영으로 보고 강하게 검사한다. 기존 `operational-policy.production-profiles`도 계속 동작한다. |
| `local-support.enabled` | `false` | local/test용 기본 token/session/rate-limit bean을 명시적으로 켠다. 운영에서는 쓰지 않는다. |


## 서비스 역할

starter는 하나만 쓰고, 역할은 설정으로 고른다. 이 값은 사용자 권한 role이 아니라 서비스 성격에 맞는 보안 기본값 묶음이다.

```yaml
platform:
  security:
    service-role-preset: api-server
```

issuer 역할의 운영 서비스는 `PlatformTokenIssuerPort`와 `PlatformSessionIssuerPort`를 직접 제공하거나, `platform-security-auth-bridge-starter`로 raw auth bean을 같은 platform port 뒤로 감싸야 한다.  
`platform-security`는 발급 흐름만 연결하고, 운영 token/session 저장소는 3계층이 소유한다. auth bridge starter를 쓸 때만 raw auth bean을 내부에서 platform-owned 발급 port와 `PlatformSessionSupportFactory` 뒤로 감싼다.

## Boundary

boundary는 URL path별 보안 구역이다.  
예를 들어 `/health`는 로그인 없이 열고, `/api/**`는 로그인 확인을 하고, `/admin/**`는 관리자 요청으로 보고, `/internal/**`는 내부 서비스 요청으로 본다.

```text
PUBLIC
-> 로그인 없이 접근 가능

PROTECTED
-> 로그인 필요

ADMIN
-> 관리자 요청

INTERNAL
-> 내부 서비스 요청
```

| 설정 | 기본값 | 쉬운 설명 |
| --- | --- | --- |
| `boundary.public-paths` | `[]` | 로그인 없이 열어둘 path |
| `boundary.protected-paths` | `[]` | 일반 로그인 보호 path |
| `boundary.admin-paths` | `[]` | 관리자 path |
| `boundary.internal-paths` | `[]` | 내부 서비스 path |

기본으로 알고 있는 path:

| Pattern | Boundary |
| --- | --- |
| `/health`, `/actuator/health` | `PUBLIC` |
| `/api`, `/api/**` | `PROTECTED` |
| `/admin`, `/admin/**` | `ADMIN` |
| `/internal`, `/internal/**` | `INTERNAL` |
| 그 외 | `PROTECTED` |

## Auth

인증 관련 설정이다.

| 설정 | 기본값 | 쉬운 설명 |
| --- | --- | --- |
| `auth.enabled` | `true` | 인증 검사를 켠다. |
| `auth.default-mode` | `HYBRID` | token/session이 섞여 있을 때 기본 처리 방식 |
| `auth.allow-session-for-browser` | `true` | 브라우저 요청에서 session 허용 |
| `auth.allow-bearer-for-api` | `true` | API 요청에서 Bearer/JWT 허용 |
| `auth.allow-api-key-for-api` | `true` | API key 허용 |
| `auth.allow-hmac-for-api` | `true` | HMAC 서명 허용 |
| `auth.allow-oidc-for-api` | `true` | OIDC ID token 허용 |
| `auth.service-account-enabled` | `true` | service account 허용 |
| `auth.internal-token-enabled` | `true` | internal token 허용 |
| `auth.dev-fallback.enabled` | `false` | local/test용 임시 사용자 확인 기능 사용 |
| `auth.jwt-secret` | dev default | local/test용 JWT secret |
| `auth.access-token-ttl` | `30m` | access token 유효 시간 |
| `auth.refresh-token-ttl` | `14d` | refresh token 유효 시간 |

`dev-fallback`은 테스트용 기본 사용자 확인 기능이다. 운영에서는 쓰지 않는다.

운영에서 `auth.enabled=true`이면 `SecurityContextResolver` bean이 반드시 필요하다.  
쉽게 말하면 “현재 요청의 사용자가 누구인지 찾는 코드”를 서비스가 제공해야 한다.

`InternalTokenClaimsValidator`, `TokenIssuanceCapability`, `SessionIssuanceCapability`, `OAuth2PrincipalBridge` 같은 공개 auth 계약은 `PlatformIssueTokenCommand`, `PlatformIssueSessionCommand`, `PlatformIssuedToken`, `PlatformSessionView`, `PlatformOAuth2UserIdentity` 같은 runtime view를 기준으로 동작한다. `PlatformAuthenticatedPrincipal`은 canonical principal 모델이 아니라 발급/검증 흐름에서만 쓰는 runtime principal view로 유지한다.

## OIDC

OIDC token 자체 검증은 3계층이 `OidcTokenVerifier` bean으로 제공한다.  
`platform-security`는 그 verifier를 공통 인증 흐름에 연결한다.

| 설정 | 기본값 | 쉬운 설명 |
| --- | --- | --- |
| `auth.oidc.principal-claim` | `sub` | 사용자 id로 볼 claim |
| `auth.oidc.authorities-claim` | `roles` | 권한 목록으로 볼 claim |
| `auth.oidc.authority-prefix` | `""` | 권한 앞에 붙일 prefix |
| `auth.oidc.default-authorities` | `[]` | claim이 없을 때 기본 권한 |

## IP Guard

IP guard는 client type을 먼저 보고, 필요하면 path boundary를 방어선으로 사용해 허용된 IP에서만 받도록 제한하는 기능이다.
`ADMIN_CONSOLE`은 admin IP rule을, `INTERNAL_SERVICE`는 internal IP rule을 우선 적용한다.
일반 `BROWSER`/`EXTERNAL_API` client의 `PROTECTED` 요청은 IP rule 없이 인증만 확인한다.

| 설정 | 기본값 | 쉬운 설명 |
| --- | --- | --- |
| `ip-guard.enabled` | `true` | IP 제한을 켠다. |
| `ip-guard.trust-proxy` | `false` | proxy가 넘긴 client IP를 사용할지 여부 |
| `ip-guard.trusted-proxy-cidrs` | `[]` | 믿을 수 있는 proxy exact IP 또는 CIDR |
| `ip-guard.admin.source` | `INLINE` | admin IP rule을 어디서 읽을지 |
| `ip-guard.admin.rules` | `[]` | admin 허용 ip-guard rule 목록 |
| `ip-guard.admin.location` | `""` | 파일에서 읽을 때 위치 |
| `ip-guard.admin.policy-key` | `""` | 정책 config에서 읽을 때 key |
| `ip-guard.internal.source` | `INLINE` | internal IP rule을 어디서 읽을지 |
| `ip-guard.internal.rules` | `[]` | internal 허용 ip-guard rule 목록 |
| `ip-guard.internal.location` | `""` | 파일에서 읽을 때 위치 |
| `ip-guard.internal.policy-key` | `""` | 정책 config에서 읽을 때 key |

운영에서는 admin/internal IP rule이 비어 있으면 시작하지 않는다.  
`trust-proxy=true`이면 `trusted-proxy-cidrs`도 운영에서 필요하다.
`trusted-proxy-cidrs`가 비어 있으면 `X-Forwarded-For`를 신뢰하지 않는다.

IP rule 선택 기준은 audit reason에도 남는다.
`policyBasis=CLIENT_TYPE`은 client type 때문에 rule이 강제된 것이고, `policyBasis=PATH`는 admin/internal path 때문에 rule이 적용된 것이다.

local/dev에서 proxy header를 테스트해야 하면 loopback proxy를 명시한다.

```yaml
platform:
  security:
    ip-guard:
      trust-proxy: true
      trusted-proxy-cidrs:
        - 127.0.0.1
        - ::1
```

### IP rule 문법

`trusted-proxy-cidrs`는 trusted proxy의 exact IP 또는 CIDR만 받는다.
client가 속한 대역이 아니라 LB, ingress, reverse proxy, service mesh proxy의 source IP 대역을 넣는다.

`admin.rules`, `internal.rules`는 ip-guard rule 문법을 사용한다.
CIDR과 range rule을 사용할 수 있다.

```yaml
platform:
  security:
    ip-guard:
      admin:
        rules:
          - 10.0.0.0/8
          - 203.0.113.10
      internal:
        rules:
          - 172.16.0.0/12
          - 2001:db8::1-2001:db8::f
```

### Proxy CIDR 설정

proxy 뒤에서 `X-Forwarded-For`를 사용하려면 profile별로 proxy 대역을 명시한다.
인프라가 바뀌면 이 값도 같이 바뀐다.

```yaml
# application-local.yml
platform:
  security:
    ip-guard:
      trust-proxy: true
      trusted-proxy-cidrs:
        - 127.0.0.1
        - ::1

# application-prod.yml
platform:
  security:
    ip-guard:
      trust-proxy: true
      trusted-proxy-cidrs:
        - <lb-or-ingress-cidr>
```

## Rate Limit

rate limit은 요청 횟수를 제한하는 기능이다.

| 설정 | 기본값 | 쉬운 설명 |
| --- | --- | --- |
| `rate-limit.enabled` | `true` | 요청 제한을 켠다. |
| `rate-limit.anonymous.requests` | `100` | 로그인 안 한 사용자 제한 횟수 |
| `rate-limit.anonymous.window-seconds` | `60` | 제한 시간 구간 |
| `rate-limit.authenticated.requests` | `100` | 로그인 사용자 제한 횟수 |
| `rate-limit.authenticated.window-seconds` | `60` | 제한 시간 구간 |
| `rate-limit.internal.requests` | `100` | 내부 서비스 요청 제한 횟수 |
| `rate-limit.internal.window-seconds` | `60` | 제한 시간 구간 |
| `rate-limit.routes[].name` | `route` | route별 제한 이름 |
| `rate-limit.routes[].patterns` | `[]` | 적용할 path |
| `rate-limit.routes[].requests` | `100` | route별 제한 횟수 |
| `rate-limit.routes[].window-seconds` | `60` | 제한 시간 구간 |

로그인처럼 public이지만 제한이 필요한 endpoint는 route limit을 추가한다.

운영 확장 표면은 `PlatformRateLimitPort`다. 기존 `RateLimiter` bean을 계속 써야 하면 `platform-security-ratelimit-bridge-starter`가 등록하는 adapter auto-configuration이 이를 `PlatformRateLimitPort` 구현으로 감싼다. policy와 운영 안전검사는 raw limiter가 아니라 platform port bean 존재와 분산 backing 여부만 본다.

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

## 운영 안전검사

아래 중 하나면 운영으로 보고 강하게 검사한다.

```text
active Spring profile이 platform.security.operational.production-profiles에 포함됨
platform.security.operational.production=true
```

기본 운영 profile은 `prod`, `production`이다. `live`는 기본 운영 profile로 해석하지 않는다.  
기존 설정 이름인 `platform.security.operational-policy.*`도 호환된다.

운영에서 막는 것:

```text
- 인증 꺼짐
- 인증 기본 모드가 NONE
- local/test용 기본 사용자 확인 기능 켜짐
- 현재 사용자 확인 코드 없음
- 개발용 TokenService 사용
- 개발용 SessionStore 사용
- local InternalTokenClaimsValidator 사용
- dev JWT secret 사용
- IP guard 꺼짐
- `trust-proxy=true`인데 trusted proxy exact IP 또는 CIDR 없음
- admin/internal IP rule 없음
- rate limit 꺼짐
- production `PlatformRateLimitPort` bean 없음
- local/test 전용 in-memory rate-limit adapter 사용
- quota가 0 이하
- route limit에 path 없음
```

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
      trusted-proxy-cidrs:
        - 10.0.0.0/8
      admin:
        source: INLINE
        rules:
          - 10.0.0.0/8
      internal:
        source: INLINE
        rules:
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
