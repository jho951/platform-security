# Architecture

`platform-security`는 1계층 security OSS를 조립해 서비스가 소비하는 보안 경계를 제공한다.

## 책임

- `platform-security-policy`
  - 공개 계약, 경계 모델, 인증 모드, 클라이언트 타입, 공통 설정을 제공한다.
- `platform-security-auth`
  - auth OSS 4개 모듈을 서비스용 인증 capability로 조립한다.
- `platform-security-ip`
  - ip-guard OSS를 서비스 경계 IP 보호 capability로 조립한다.
- `platform-security-rate-limit`
  - rate-limiter OSS를 서비스 요청 제한 capability로 조립한다.
- `platform-security-web`
  - HTTP / Servlet 경계 적응, ingress 해석, downstream header 준비를 담당한다.
- `platform-security-auth-adapter`
  - auth-server 헤더/클레임을 `SecurityContext`로 변환한다.
  - 고정 입력 헤더는 `Authorization`, `X-Auth-Session-Id`, `X-Auth-Authenticated`, `X-Auth-Principal`, `X-Auth-Roles`다.
- `platform-security-autoconfigure`
  - 1계층 OSS와 platform 내부 모듈을 Spring bean으로 조립한다.
- `platform-security-starter`
  - 소비 진입점을 제공한다.
- `platform-security-test-support`
  - 공용 테스트 fixture를 제공한다.

## 원칙

- platform은 private 레포다.
- 1계층 OSS의 의미를 다시 정의하지 않는다.
- 서비스는 `platform.security.*` 설정과 policy 입력만 공급한다.
- 1계층 artifact는 exact version으로만 소비한다.
- notification은 다른 communication OSS로 분리 유지한다.
- auth, ip-guard, rate-limiter는 서비스 진입 보안만 담당한다.

## 조립 흐름

1. `platform-security-autoconfigure`가 published OSS artifact를 bean으로 가져온다.
2. `platform-security-policy`가 auth, ip-guard, rate-limiter 순서를 고정한다.
3. `platform-security-web`가 client IP와 boundary를 해석한다.
4. `platform-security-auth-adapter`가 auth OSS 4개 모듈과 auth-server 응답을 `SecurityContext`로 변환한다.
5. 실패 응답은 401, 403, 429 중 하나로 표준화한다.
6. downstream 신원 전달은 허용된 요청에만 적용한다.

## 현재 구현

- `platform-security-policy`: 공개 계약
- `platform-security-auth`: auth capability 조립
- `platform-security-ip`: IP 보호 capability 조립
- `platform-security-rate-limit`: rate limit capability 조립
- `platform-security-web`: ingress / boundary / downstream 어댑터
- `platform-security-auth-adapter`: auth-server context resolver
- `platform-security-autoconfigure`: Spring 자동 구성
- `platform-security-starter`: 진입점
- `platform-security-test-support`: 테스트 픽스처
