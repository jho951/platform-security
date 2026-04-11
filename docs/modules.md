# Modules

## 모듈

- `platform-security-bom`: 버전 정렬
- `platform-security-policy`: 공통 경계/모델/설정
- `platform-security-auth`: auth capability 조립
- `platform-security-ip`: IP 보호 capability 조립
- `platform-security-rate-limit`: rate limit capability 조립
- `platform-security-web`: HTTP / Servlet 어댑터와 ingress 변환
- `platform-security-auth-adapter`: auth-server context resolver
- `platform-security-autoconfigure`: Spring boot auto-configuration
- `platform-security-starter`: starter 진입점
- `platform-security-test-support`: 테스트 픽스처와 샘플

## 읽는 법

- 공통 모델과 상위 의미를 보려면 `platform-security-policy`부터 본다.
- 인증 조립은 `platform-security-auth`를 본다.
- IP 보호 조립은 `platform-security-ip`를 본다.
- rate limit 조립은 `platform-security-rate-limit`를 본다.
- HTTP 진입점과 downstream 전달을 보려면 `platform-security-web`를 본다.
- Spring 조립과 bean wiring을 보려면 `platform-security-autoconfigure`를 본다.
- 테스트 도움말은 `platform-security-test-support`를 본다.

## 책임 경계

- `platform-security-policy`
  - 경계 계약만 둔다.
  - 구현 세부와 Spring 타입을 넣지 않는다.
- `platform-security-auth`
  - auth OSS 4개 모듈을 서비스용 인증 capability로 조립한다.
- `platform-security-ip`
  - 클라이언트 IP와 boundary별 IP 정책을 capability로 제공한다.
- `platform-security-rate-limit`
  - boundary와 client type별 rate limit capability를 제공한다.
- `platform-security-web`
  - ingress 해석과 header / response 적응만 둔다.
  - auth, ip-guard, rate-limiter 정책 자체는 넣지 않는다.
- `platform-security-auth-adapter`
  - auth-server 헤더/클레임을 `SecurityContext`로 바꾼다.
- `platform-security-autoconfigure`
  - 빈 등록과 조립만 담당한다.
  - 비즈니스 정책을 다시 정의하지 않는다.
- `platform-security-test-support`
  - 테스트 데이터와 fixture를 제공한다.
