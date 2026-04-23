# Modules

## 2계층 사용법

서비스는 BOM과 base starter를 사용한다.

```gradle
dependencies {
    implementation platform("io.github.jho951.platform:platform-security-bom:${version}")
    implementation "io.github.jho951.platform:platform-security-starter"
}
```

역할은 starter가 아니라 설정으로 고른다. `platform.security.role`처럼 짧은 이름은 RBAC role과 헷갈릴 수 있으므로 쓰지 않는다.

```yaml
platform:
  security:
    service-role-preset: api-server
```

사용 가능한 preset은 `edge`, `issuer`, `api-server`, `internal-service`다.

## 모듈 분리 기준

```text
auth 구현 의존성
IP rule engine 의존성
rate limiter 의존성
Servlet/WebFlux 경계
Spring Boot auto-configuration
local/test 전용 구현
```

## 3계층이 추가로 붙일 수 있는 것

| Artifact | 언제 쓰나 |
| --- | --- |
| `platform-security-client` | 다른 서비스로 호출할 때 표준 사용자 header를 자동으로 붙이고 싶을 때 |
| `platform-security-auth-bridge-starter` | raw auth bean을 platform port에 연결하는 bridge starter가 필요할 때 |
| `platform-security-ratelimit-bridge-starter` | raw rate limiter bean을 platform port에 연결하는 bridge starter가 필요할 때 |
| `platform-security-hybrid-web-adapter` | gateway/edge가 hybrid mode에서 Servlet 또는 WebFlux ingress를 공식 bundle로 받아 직접 조립하고 싶을 때 |
| `platform-security-web-api` | custom failure writer나 ingress contributor 같은 web extension contract만 직접 쓰고 싶을 때 |
| `platform-security-legacy-compat` | 제거 예정인 legacy secret compat를 platform-owned optional seam으로 잠시 유지해야 할 때 |
| `platform-security-support-local` | local/test에서만 기본 token/session/rate-limit 구현을 쓰고 싶을 때. 운영 `implementation` 금지 |
| `platform-security-governance-bridge` | 보안 차단 기록을 governance audit에 같이 남기고 싶을 때. `platform-integrations` repository에서 별도 bridge artifact로 추가 |
| `platform-security-policyconfig-bridge` | IP rule 같은 정책 읽기를 공통 policy config에서 하고 싶을 때 |
| `platform-security-test-support` | 테스트 fixture가 필요할 때 |

## 3계층이 직접 조립하지 않는 것

아래 모듈은 `platform-security-starter`가 내부에서 끌고 온다.
서비스가 직접 의존해서 조립할 필요가 없다.

```text
platform-security-policy
platform-security-api
platform-security-ports
platform-security-core
platform-security-ip
platform-security-web
platform-security-autoconfigure
platform-security-issuer-autoconfigure
platform-security-internal-autoconfigure
platform-policy-api
```

`platform-security-ports`는 공개 auth/rate-limit 계약과 runtime view를 담고, `platform-security-core`는 그 port만 보고 runtime을 조립한다.
`platform-security-client`, `platform-security-auth-bridge-starter`, `platform-security-ratelimit-bridge-starter`, `platform-security-legacy-compat`, `platform-security-hybrid-web-adapter`는 stage-5 기준의 optional add-on이다.

3계층은 내부 class를 직접 import하지 않고, 공개 API, 공개 bean, `platform.security.*` 설정으로 차이를 표현한다.

## 배포하지 않는 예제 모듈

```text
platform-security-sample-consumer
```

이 모듈은 사용 예시라서 package로 배포하지 않는다.

## 외부 보안 의존성 버전

`platform-security` 내부 모듈이 사용하는 외부 보안 라이브러리 버전이다.

| Property | 현재 값 |
| --- | --- |
| `auth_version` | `3.0.1` |
| `ipGuard_version` | `3.0.0` |
| `rateLimiter_version` | `2.0.0` |
