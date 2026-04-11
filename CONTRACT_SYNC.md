# CONTRACT_SYNC - platform-security

## 기준

- `oss-contract`: 2계층 platform 표준

## 반영 대상

- `README.md`
- `docs/README.md`
- `docs/architecture.md`
- `docs/modules.md`
- `docs/security-model.md`
- `docs/configuration.md`
- `docs/extension-guide.md`
- `docs/troubleshooting.md`
- `build.gradle`
- `settings.gradle`
- `.github/workflows/build.yml`

## 전제

- `platform-security`는 private platform 레포다.
- `auth`, `ip-guard`, `rate-limiter`의 Maven Central 배포본을 조립한다.
- 로컬 소스 레포에 대한 `project()` 직접 의존은 두지 않는다.
- `notification`은 communication OSS로 분리 유지한다.
- 2계층 platform은 1계층 OSS의 consumer-facing 조립 계층이다.
- 2계층은 외부 공개 라이브러리로 배포하지 않는다.
- 2계층 공개 표면은 `properties`, `customizer`, `override bean`만 허용한다.
- 2계층은 서비스별 비즈니스 로직, 도메인 권한 판단, 회원가입, 토큰 발급 비즈니스, 특정 서비스 URL, Redis key 규칙을 포함하지 않는다.
- 2계층 버전은 내부 서비스 간 호환성을 우선한다.

## 의존성 기준

- `auth`: `io.github.jho951:auth-core:3.0.0`, `io.github.jho951:auth-jwt:3.0.0`, `io.github.jho951:auth-session:3.0.0`, `io.github.jho951:auth-hybrid:3.0.0`
- `ip-guard`: `io.github.jho951:ip-guard-core:2.0.5`, `io.github.jho951:ip-guard-spi:2.0.5`
- `rate-limiter`: `io.github.jho951:rate-limiter-core:1.1.1`, `io.github.jho951:rate-limiter-spi:1.1.1`
