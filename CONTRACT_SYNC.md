# CONTRACT_SYNC - platform-security

## 기준

- `oss-contract`: 2계층 platform 표준

## 반영 대상

- `README.md`
- `docs/README.md`
- `docs/architecture.md`
- `docs/quickstart.md`
- `docs/auth-server-integration.md`
- `docs/private-publish.md`
- `docs/modules.md`
- `docs/security-model.md`
- `docs/configuration.md`
- `docs/extension-guide.md`
- `docs/troubleshooting.md`
- `build.gradle`
- `settings.gradle`
- `.github/workflows/publish.yml`

## 전제

- `platform-security`는 private platform 레포다.
- `auth`, `ip-guard`, `rate-limiter`의 Maven Central 배포본을 조립한다.
- 로컬 소스 레포에 대한 `project()` 직접 의존은 두지 않는다.
- `notification`은 communication OSS로 분리 유지한다.
- 2계층 platform은 1계층 OSS의 consumer-facing 조립 계층이다.
- 2계층은 외부 공개 라이브러리로 배포하지 않는다.
- 2계층 공개 표면은 `properties`, `customizer`, `override bean`만 허용한다.
- 2계층은 서비스별 비즈니스 로직, 도메인 권한 판단, 회원가입, 토큰 발급 비즈니스, 특정 서비스 URL, Redis key 규칙을 포함하지 않는다.
- 2계층은 token/session 발급 비즈니스가 아니라, 1계층 `TokenService`와 `SessionStore`를 조립하는 issuance capability만 제공할 수 있다.
- OAuth2 login flow, provider token exchange, user provisioning, redirect/cookie 정책은 3계층 서비스 책임이다.
- 2계층은 OAuth2 결과를 표준 principal로 변환하는 bridge까지만 제공할 수 있다.
- PUBLIC boundary라도 login/refresh/oauth2-start 같은 abuse-sensitive route는 `rate-limit.routes[]`로 별도 제한할 수 있다.
- internal service token의 issuer/audience/service-id 같은 조직별 검증은 `InternalTokenClaimsValidator` override로 흡수한다.
- downstream identity propagation과 audit event 발행은 2계층 web extension point로 제공하되, 서비스별 저장소/로그 포맷은 강제하지 않는다.
- 2계층 버전은 내부 서비스 간 호환성을 우선한다.
- 운영 환경에서 `SecurityContextResolver`가 없으면 fail-fast 한다.
- dev fallback resolver는 local/test opt-in으로만 허용한다.

## 의존성 기준

- `auth`: `io.github.jho951:auth-core:3.0.1`, `io.github.jho951:auth-jwt:3.0.1`, `io.github.jho951:auth-session:3.0.1`, `io.github.jho951:auth-hybrid:3.0.1`, `io.github.jho951:auth-apikey:3.0.1`, `io.github.jho951:auth-hmac:3.0.1`, `io.github.jho951:auth-oidc:3.0.1`, `io.github.jho951:auth-service-account:3.0.1`
- `ip-guard`: `io.github.jho951:ip-guard-core:3.0.0`, `io.github.jho951:ip-guard-spi:3.0.0`
- `rate-limiter`: `io.github.jho951:rate-limiter-core:2.0.0`, `io.github.jho951:rate-limiter-spi:2.0.0`

## 비공개 배포 기준

- GitHub Packages private Maven registry를 사용한다.
- `v*` tag push가 publish workflow를 실행한다.
- `platform-security-sample-consumer`는 publish 대상이 아니다.
- 현재 확인된 private publish tag는 `v1.0.2`이다.
- GitHub Actions publish는 `GITHUB_ACTOR=${{ github.actor }}`와 `GITHUB_TOKEN=${{ secrets.GITHUB_TOKEN }}`를 사용한다.
- private consumer는 `GITHUB_ACTOR`와 `GITHUB_TOKEN` 또는 `GH_PACKAGES_TOKEN` secret으로 GitHub Packages를 인증한다.
