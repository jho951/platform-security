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

## 의존성 기준

- `auth`: `io.github.jho951:auth-core:3.0.0`, `io.github.jho951:auth-jwt:3.0.0`, `io.github.jho951:auth-session:3.0.0`, `io.github.jho951:auth-hybrid:3.0.0`
- `ip-guard`: `io.github.jho951:ip-guard-core:3.0.0`, `io.github.jho951:ip-guard-spi:3.0.0`
- `rate-limiter`: `io.github.jho951:rate-limiter-core:2.0.0`, `io.github.jho951:rate-limiter-spi:2.0.0`
