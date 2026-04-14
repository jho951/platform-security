# Modules

이 문서는 모듈의 역할과 서비스가 직접 의존할 artifact를 설명한다. 설계 원칙은 [architecture.md](./architecture.md)를 본다.

## 소비용 artifact

3계층 서비스는 보통 아래 조합을 사용한다.

```gradle
dependencies {
    implementation platform("io.github.jho951.platform:platform-security-bom:1.0.4")
    implementation "io.github.jho951.platform:platform-security-resource-server-starter"
}
```

역할별 starter는 서비스의 모든 endpoint 종류가 아니라 주 역할(primary role)을 고르는 진입점이다.

| Artifact | 용도 |
| --- | --- |
| `platform-security-edge-starter` | 외부 트래픽을 받는 edge/gateway가 주 역할인 서비스 |
| `platform-security-issuer-starter` | token/session issuer가 주 역할인 서비스 |
| `platform-security-resource-server-starter` | 일반 resource API가 주 역할인 서비스 |
| `platform-security-internal-service-starter` | 전체 서비스가 내부 호출 전용인 서비스 |

일반 starter:

| Artifact | 용도 |
| --- | --- |
| `platform-security-starter` | preset을 직접 설정하고 싶을 때 |

역할별 starter는 둘 이상 동시에 쓰면 fail-fast 된다. 한 서비스 안에 internal endpoint가 일부 있다고 해서 `internal-service-starter`를 추가하지 않는다. 예를 들어 auth-server는 `issuer-starter` 하나를 쓰고, 내부 API는 `boundary.internal-paths`와 `internal-allow-cidrs`로 선언한다.

## 내부 모듈

| Module | 책임 |
| --- | --- |
| `platform-security-policy` | 공통 모델, 설정, SPI, preset, 운영정책 enforcer |
| `platform-security-api` | 런타임 요청/결과 계약 |
| `platform-security-core` | policy chain 평가 엔진 |
| `platform-security-auth` | auth 1계층 provider를 platform capability로 조립 |
| `platform-security-ip` | boundary/profile 기반 IP guard 조립 |
| `platform-security-rate-limit` | boundary/profile/route 기반 rate limit 조립 |
| `platform-security-web` | Servlet/WebFlux ingress, header scrub, response, downstream propagation |
| `platform-security-autoconfigure` | Spring bean 조립과 fail-fast guard |
| `platform-security-test-support` | 테스트 fixture |
| `platform-security-sample-consumer` | 소비 예제 |

`platform-security-api`와 `platform-security-core`는 내부 지원층이다. 서비스는 starter와 공개 SPI를 통해 사용한다.

## 배포 대상

Private GitHub Packages publish 대상:

- `platform-security-bom`
- `platform-security-policy`
- `platform-security-api`
- `platform-security-core`
- `platform-security-auth`
- `platform-security-ip`
- `platform-security-rate-limit`
- `platform-security-web`
- `platform-security-autoconfigure`
- `platform-security-starter`
- `platform-security-edge-starter`
- `platform-security-issuer-starter`
- `platform-security-resource-server-starter`
- `platform-security-internal-service-starter`
- `platform-security-test-support`

Publish 제외:

- `platform-security-sample-consumer`

## 1계층 OSS 버전

버전은 [gradle.properties](../gradle.properties)에서 관리한다.

| Property | 현재 값 |
| --- | --- |
| `auth_version` | `3.0.1` |
| `ipGuard_version` | `3.0.0` |
| `rateLimiter_version` | `2.0.0` |
