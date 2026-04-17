# Modules

이 문서는 어떤 artifact를 3계층 서비스가 직접 쓰면 되는지 설명한다.

## 3계층이 보통 쓰는 것

서비스는 BOM과 starter 하나를 사용한다.

```gradle
dependencies {
    implementation platform("io.github.jho951.platform:platform-security-bom:${version}")
    implementation "io.github.jho951.platform:platform-security-resource-server-starter"
}
```

## Starter 선택

| Starter | 언제 쓰나 |
| --- | --- |
| `platform-security-edge-starter` | 외부 요청이 처음 들어오는 gateway/edge 서비스 |
| `platform-security-issuer-starter` | 로그인 후 token/session을 발급하는 서비스 |
| `platform-security-resource-server-starter` | 일반 API를 제공하는 서비스 |
| `platform-security-internal-service-starter` | 서비스 전체가 내부 호출 전용인 서비스 |
| `platform-security-starter` | 역할을 설정으로 직접 정하고 싶을 때 |

starter는 하나만 고른다.

예:

```text
issuer 서비스에 /internal/** API가 있어도
-> issuer-starter 하나만 사용
-> /internal/** 는 boundary.internal-paths로 선언
```

## 3계층이 추가로 붙일 수 있는 것

| Artifact | 언제 쓰나 |
| --- | --- |
| `platform-security-client` | 다른 서비스로 호출할 때 표준 사용자 header를 자동으로 붙이고 싶을 때 |
| `platform-security-local-support` | local/test에서만 기본 token/session/rate-limit 구현을 쓰고 싶을 때. 운영 `implementation` 금지 |
| `platform-security-governance-bridge` | 보안 차단 기록을 governance audit에 같이 남기고 싶을 때 |
| `platform-security-policyconfig-bridge` | IP rule 같은 정책 읽기를 공통 policy config에서 하고 싶을 때 |
| `platform-security-test-support` | 테스트 fixture가 필요할 때 |

## 3계층이 직접 조립하지 않는 것

아래 모듈은 `starter`가 내부에서 끌고 온다.  
서비스가 직접 의존해서 조립할 필요가 없다.

```text
platform-security-policy
platform-security-api
platform-security-core
platform-security-auth
platform-security-ip
platform-security-rate-limit
platform-security-web
platform-security-autoconfigure
platform-security-issuer-autoconfigure
platform-security-internal-autoconfigure
platform-policy-api
```

3계층은 내부 class를 직접 import하지 않고, 공개 API, 공개 bean, `platform.security.*` 설정으로 차이를 표현한다.

## 배포하지 않는 예제 모듈

```text
platform-security-sample-consumer
```

이 모듈은 사용 예시라서 package로 배포하지 않는다.

## 1계층 버전

`platform-security`가 소비하는 1계층 OSS 버전이다.

| Property | 현재 값 |
| --- | --- |
| `auth_version` | `3.0.1` |
| `ipGuard_version` | `3.0.0` |
| `rateLimiter_version` | `2.0.0` |
