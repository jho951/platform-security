# Architecture

`platform-security`는 1계층 security OSS를 조립해 서비스가 소비하는 보안 경계를 제공한다.
이 레포와 2계층 산출물은 내부 비공개 플랫폼으로 보는 것이 기본이다.

## 책임

- `platform-security-policy`
  - 공통 계약, 경계 모델, 인증 모드, 클라이언트 타입, 공통 설정을 제공한다.
- `platform-security-auth`
  - auth OSS 4개 모듈을 서비스용 인증 capability로 조립한다.
- `platform-security-ip`
  - ip-guard OSS를 서비스 경계 IP 보호 capability로 조립한다.
- `platform-security-rate-limit`
  - rate-limiter OSS를 서비스 요청 제한 capability로 조립한다.
- `platform-security-web`
  - HTTP / Servlet / WebFlux 경계 적응, ingress 해석, downstream header 준비를 담당한다.
- `platform-security-autoconfigure`
  - 1계층 OSS와 platform 내부 모듈을 Spring bean으로 조립한다.
- `platform-security-starter` (thin dependency aggregator)
  - 소비 진입점을 제공한다.
- `platform-security-test-support`
  - 공용 테스트 fixture를 제공한다.

## 원칙

- platform은 private 레포다.
- 2계층은 내부 서비스 공통 플랫폼 레이어다.
- 2계층은 외부 공개 라이브러리로 배포하지 않는다.
- 1계층 OSS의 의미를 다시 정의하지 않는다.
- 서비스는 `platform.security.*` 설정과 policy 입력만 공급한다.
- 1계층 artifact는 exact version으로만 소비한다.
- notification은 다른 communication OSS로 분리 유지한다.
- auth, ip-guard, rate-limiter는 서비스 진입 보안만 담당한다.
- 2계층 공개 표면은 `properties`, `customizer`, `override bean`으로만 확장한다.
- 2계층은 서비스별 비즈니스 로직, 도메인 권한 판단, 회원가입, 토큰 발급 비즈니스, 특정 서비스 URL, Redis key 규칙을 포함하지 않는다.
- 2계층 버전은 내부 서비스 간 호환성을 우선한다.

## 조립 흐름

1. `platform-security-autoconfigure`가 published OSS artifact를 bean으로 가져온다.
2. `platform-security-policy`가 auth, ip-guard, rate-limiter 순서를 고정한다.
3. `platform-security-web`가 client IP와 boundary를 해석한다.
4. 실패 응답은 401, 403, 429 중 하나로 표준화한다.
5. downstream 신원 전달은 허용된 요청에만 적용한다.

## 현재 구현

- `platform-security-policy`: 공통 계약
- `platform-security-auth`: auth capability 조립
- `platform-security-ip`: IP 보호 capability 조립
- `platform-security-rate-limit`: rate limit capability 조립
- `platform-security-web`: ingress / boundary / downstream 어댑터(Servlet / WebFlux)
- `platform-security-autoconfigure`: Spring 자동 구성
- `platform-security-starter`: 얇은 dependency aggregator
- `platform-security-test-support`: 테스트 픽스처
