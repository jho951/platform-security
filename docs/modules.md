# Modules

## 모듈

- `platform-security-bom`: 버전 정렬
- `platform-security-policy`: 공통 경계/모델/설정
- `platform-security-auth`: auth capability 조립
- `platform-security-ip`: IP 보호 capability 조립
- `platform-security-rate-limit`: rate limit capability 조립
- `platform-security-web`: HTTP / Servlet / WebFlux 어댑터와 ingress 변환
- `platform-security-autoconfigure`: Spring boot auto-configuration
- `platform-security-starter`: 얇은 dependency aggregator
- `platform-security-test-support`: 테스트 픽스처와 샘플
- `platform-security-sample-consumer`: 2계층 사용 예제 소비자
- `platform-security-api`: 내부 런타임 계약
- `platform-security-core`: 내부 평가 엔진

## 내부 좌표

- `io.github.jho951.platform:platform-security-bom`
- `io.github.jho951.platform:platform-security-policy`
- `io.github.jho951.platform:platform-security-auth`
- `io.github.jho951.platform:platform-security-ip`
- `io.github.jho951.platform:platform-security-rate-limit`
- `io.github.jho951.platform:platform-security-web`
- `io.github.jho951.platform:platform-security-autoconfigure`
- `io.github.jho951.platform:platform-security-starter`
- `io.github.jho951.platform:platform-security-test-support`

`platform-security-api`와 `platform-security-core`는 내부 지원층이다. 서비스가 직접 바라보는 기본 진입점은 `platform-security-starter`다.

## 읽는 법

- 공통 모델과 상위 의미를 보려면 `platform-security-policy`부터 본다.
- 인증 조립은 `platform-security-auth`를 본다.
- IP 보호 조립은 `platform-security-ip`를 본다.
- rate limit 조립은 `platform-security-rate-limit`를 본다.
- HTTP / Reactive 진입점과 downstream 전달을 보려면 `platform-security-web`를 본다.
- Spring 조립과 bean wiring을 보려면 `platform-security-autoconfigure`를 본다.
- 테스트 도움말은 `platform-security-test-support`를 본다.
- 실제 소비 예제는 `platform-security-sample-consumer`를 본다.
- 서비스가 직접 의존할 모듈은 보통 `platform-security-starter`와 `platform-security-bom`이다.

## 책임 경계

- `platform-security-policy`
  - 경계 계약만 둔다.
  - 구현 세부와 Spring 타입을 넣지 않는다.
  - boundary, auth mode, client type, common properties를 정의한다.
  - `SecurityBoundaryResolver`, `ClientTypeResolver`, `AuthenticationModeResolver`, `ClientIpResolver`, `RateLimitKeyResolver` 같은 override point를 정의한다.
- `platform-security-auth`
  - auth OSS 8개 모듈을 서비스용 인증 capability로 조립한다.
  - `PlatformSecurityContextResolvers`로 운영용 resolver 조립 지식을 제공한다.
  - 회원가입, 토큰 발급 비즈니스, 서비스별 권한 판단은 넣지 않는다.
- `platform-security-ip`
  - 클라이언트 IP와 boundary별 IP 정책을 capability로 제공한다.
  - 서비스별 URL, Redis key, 도메인 판단은 넣지 않는다.
- `platform-security-rate-limit`
  - boundary와 client type별 rate limit capability를 제공한다.
  - 서비스별 도메인 정책은 넣지 않는다.
- `platform-security-sample-consumer`
  - gateway/auth-server 형태의 소비 예제를 제공한다.
  - override 가능한 resolver/provider 사용 예시를 담는다.
- `platform-security-web`
  - ingress 해석과 header / response 적응만 둔다.
  - auth, ip-guard, rate-limiter 정책 자체는 넣지 않는다.
- `platform-security-autoconfigure`
  - 빈 등록과 조립만 담당한다.
  - 운영에서 resolver가 없으면 fail-fast 한다.
  - dev fallback은 opt-in일 때만 등록한다.
  - 비즈니스 정책을 다시 정의하지 않는다.
- `platform-security-test-support`
  - 테스트 데이터와 fixture를 제공한다.
- `platform-security-api`
  - `SecurityRequest`, `SecurityContext`, `SecurityEvaluationResult`, `ResolvedSecurityProfile`을 제공한다.
  - 공개 소비 표면이 아니라 platform 내부 지원 계약으로 취급한다.
- `platform-security-core`
  - `DefaultSecurityEvaluationService`로 boundary/client/auth-mode 기반 capability chain을 실행한다.
  - Servlet, Spring, Redis, DB를 직접 알지 않는다.

## 배포 대상

GitHub Packages private publish 대상:

- `platform-security-bom`
- `platform-security-policy`
- `platform-security-auth`
- `platform-security-ip`
- `platform-security-rate-limit`
- `platform-security-web`
- `platform-security-autoconfigure`
- `platform-security-starter`
- `platform-security-test-support`
- 내부 지원 모듈: `platform-security-api`, `platform-security-core`

publish 제외:

- `platform-security-sample-consumer`

## 1계층 OSS 의존성

- `ip-guard`: `io.github.jho951:ip-guard-core:3.0.0`, `io.github.jho951:ip-guard-spi:3.0.0`
- `rate-limiter`: `io.github.jho951:rate-limiter-core:2.0.0`, `io.github.jho951:rate-limiter-spi:2.0.0`
- `auth`: `io.github.jho951:auth-core:3.0.1`, `io.github.jho951:auth-jwt:3.0.1`, `io.github.jho951:auth-session:3.0.1`, `io.github.jho951:auth-hybrid:3.0.1`, `io.github.jho951:auth-apikey:3.0.1`, `io.github.jho951:auth-hmac:3.0.1`, `io.github.jho951:auth-oidc:3.0.1`, `io.github.jho951:auth-service-account:3.0.1`
