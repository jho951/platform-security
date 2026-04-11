# Extension Guide

## 추가 가능

- 새로운 boundary rule
- 새로운 security profile
- 새로운 auth policy / ip policy / rate-limit policy
- 새로운 identity propagation strategy
- 새로운 failure response writer
- 새로운 HTTP / Servlet adapter
- boundary/clientType/authMode profile-aware resolver/provider override
- `properties`, `customizer`, `override bean` 기반 확장

## 서비스가 공급하는 것

- boundary pattern
- profile 값
- trusted proxy 목록
- rate-limit key 전략
- downstream 전달 방식

## 추가 순서

1. 내부 공통 계약과 공통 모델이 필요하면 `platform-security-policy`에 먼저 추가한다.
2. capability 조립이 필요하면 `platform-security-auth`, `platform-security-ip`, `platform-security-rate-limit`에 넣는다.
3. HTTP / Servlet 적응이 필요하면 `platform-security-web`에 넣는다.
4. Spring 노출이 필요하면 `platform-security-autoconfigure`에서 조건부 빈으로 등록한다.
5. `docs/security-model.md`와 `docs/modules.md`를 함께 갱신한다.

## 주의점

- policy와 capability 모듈에 Spring 의존성을 넣지 않는다.
- engine은 Servlet / Spring 타입을 몰라야 한다.
- policy는 결정 이유를 설명할 수 있어야 한다.
- rate limit은 시간 의존성을 주입 가능하게 유지한다.
- provider는 boundary만 보지 말고 profile-aware overload를 제공할 수 있어야 한다.
- 서비스별 URL, Redis key, role 이름은 추가하지 않는다.
- 1계층 OSS의 내부 구현을 여기서 다시 정의하지 않는다.
- 2계층은 공개 라이브러리보다 내부 플랫폼이라는 기준으로 설계한다.
- 서비스별 비즈니스 로직과 도메인 권한 판단은 추가하지 않는다.
