# Modules

이 문서는 모듈의 역할과 서비스가 직접 의존할 artifact를 설명한다. 설계 원칙은 [architecture.md](./architecture.md)를 본다.

## 배포 대상

### 소비용 artifact

```gradle
dependencies {
    implementation platform("io.github.jho951.platform:platform-security-bom:${version}")
    implementation "io.github.jho951.platform:platform-security-*-starter"
}
```

| Artifact                                     | 용도                                 |
|----------------------------------------------|------------------------------------|
| `platform-security-edge-starter`             | 외부 트래픽을 받는 edge/gateway가 주 역할인 서비스 |
| `platform-security-issuer-starter`           | token/session issuer가 주 역할인 서비스    |
| `platform-security-resource-server-starter`  | 일반 resource API가 주 역할인 서비스         |
| `platform-security-internal-service-starter` | 전체 서비스가 내부 호출 전용인 서비스              |
| `platform-security-starter`                  | preset을 직접 설정하고 싶을 때               |

역할별 starter는 둘 이상 동시에 쓰면 fail-fast 된다.

예를 들어 auth-server는 `issuer-starter` 하나를 쓰고, 내부 API는 `boundary.internal-paths`와 internal IP rule로 선언한다. .

### 내부 모듈

| Module                                | 책임                                                                      |
|---------------------------------------|-------------------------------------------------------------------------|
| `platform-security-policy`            | 공통 모델, 설정, SPI, preset, 운영정책 enforcer                                   |
| `platform-security-api`               | 런타임 요청/결과 계약                                                            |
| `platform-security-core`              | policy chain 평가 엔진                                                      |
| `platform-security-auth`              | auth 1계층 provider를 platform capability로 조립                              |
| `platform-security-ip`                | boundary/profile 기반 IP guard 조립                                         |
| `platform-security-rate-limit`        | boundary/profile/route 기반 rate limit 조립                                 |
| `platform-security-web`               | Servlet/WebFlux ingress, header scrub, response, downstream propagation |
| `platform-security-autoconfigure`     | Spring bean 조립과 fail-fast guard                                         |
| `platform-security-governance-bridge` | security evaluation 결과를 governance audit으로 연결                           |
| `platform-security-test-support`      | 테스트 fixture                                                             |
| `platform-security-sample-consumer`   | 소비 예제                                                                   |

## 제외 대상

- `platform-security-sample-consumer`

## 1계층 OSS 버전

| Property              | 현재 값    |
|-----------------------|---------|
| `auth_version`        | `3.0.1` |
| `ipGuard_version`     | `3.0.0` |
| `rateLimiter_version` | `2.0.0` |
