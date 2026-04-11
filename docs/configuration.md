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
- `auth.internal-token-enabled`
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

## 설계 관점

- `boundary.*`는 요청 경계 분류 입력이다.
- `auth.*`는 인증 capability의 기본 정책이다.
- `ip-guard.*`는 boundary/profile에 따라 전달되는 IP 정책 입력이다.
- `rate-limit.*`는 profile이 선택한 quota 입력이다.
- 서비스별 boundary pattern, trusted proxy, downstream 전달 규칙은 application이 공급한다.

## 기본 동작

- authentication은 기본 활성화
- IP guard는 기본 활성화
- rate limit은 기본 활성화

## 설정 예시

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
      jwt-secret: platform-security-dev-secret-platform-security-dev-secret
      access-token-ttl: PT30M
      refresh-token-ttl: P14D

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
      jwt-secret: platform-security-dev-secret-platform-security-dev-secret
      access-token-ttl: PT30M
      refresh-token-ttl: P14D

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
```

## 서비스별 해석

- `gateway-server`는 외부 진입점이라 public/auth/ip/rate-limit을 강하게 적용한다.
- `auth-server`는 로그인/토큰 갱신 엔드포인트를 public boundary로 둔다.
- 두 서비스 모두 같은 starter를 사용하고, properties와 override bean으로 차이를 흡수한다.
