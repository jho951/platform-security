# Architecture

`platform-security`는 2계층 플랫폼이다. 목표는 여러 3계층 서비스가 같은 방식으로 보안 정책을 적용하도록 공통 프레임을 제공하는 것이다.

## 계층 책임

2계층이 맡는 것:

- 공통 정책 모델
- 공통 실행 체인
- 공통 starter와 auto-configuration
- 공통 interface/SPI
- 안전한 기본값
- 운영 fail-fast 규칙
- 역할별 preset
- 서비스별 선언 포인트

3계층이 맡는 것:

- 어떤 starter를 쓸지 선택
- 환경별 설정 주입
- 서비스별 boundary 세분화
- custom policy 연결
- 컨트롤러, 유스케이스, 도메인 구현
- 서비스별 저장소와 외부 연동 구성
- 도메인 권한 판단

## 설계 원칙

- 2계층은 서비스 이름을 몰라야 한다.
- 2계층은 도메인 규칙을 몰라야 한다.
- 2계층은 기본값을 제공하되 3계층 override를 허용해야 한다.
- 2계층은 조립 계층이지 업무 계층이 아니다.
- 2계층 내부도 core, runtime, autoconfigure, starter로 나눈다.

좋은 예:

- `EDGE` preset
- `ISSUER` preset
- `RESOURCE_SERVER` preset
- `INTERNAL_SERVICE` preset
- `SecurityContextResolver` SPI
- `RateLimitKeyResolver` SPI

나쁜 예:

- `gateway-server` 전용 if문
- `block-server` 문서 소유자 판단
- `user-server` 본인 프로필 수정 규칙
- 특정 서비스 URL 하드코딩

## 요청 처리 흐름

1. HTTP 요청을 `SecurityRequest`로 변환한다.
2. ingress에서 신뢰하면 안 되는 downstream identity header를 제거한다.
3. client IP를 해석한다.
4. boundary를 결정한다.
5. client type을 결정한다.
6. auth mode를 결정한다.
7. authentication, IP guard, rate limit 정책 체인을 실행한다.
8. 실패 응답을 401, 403, 429 중 하나로 표준화한다.
9. 허용된 요청에만 downstream identity header를 만든다.

## 운영 안전성

운영정책은 `OperationalSecurityPolicyEnforcer`가 직접 강제한다.

운영으로 판단하는 조건:

- active profile이 `prod`, `production`, `live` 중 하나
- 또는 `platform.security.operational-policy.production=true`

운영에서 금지되는 것:

- `SecurityContextResolver` 누락
- dev fallback resolver 사용
- `auth.default-mode=NONE`
- auth, IP guard, rate limit 비활성화
- 비어 있는 admin/internal CIDR
- 플랫폼 기본 `TokenService`를 쓰면서 dev JWT secret 사용
- 0 이하 rate limit quota

## 서비스 적용 방식

3계층 서비스는 `platform-security-bom`과 starter 하나를 선택한다.

역할별 starter는 서비스의 주 역할(primary role)을 표현한다. 서비스 안에 여러 boundary가 있을 수 있지만 starter는 하나만 선택하고, endpoint별 차이는 `boundary.*`, `rate-limit.routes[]`, override bean으로 선언한다.

역할이 명확하지 않으면 일반 `platform-security-starter`를 사용하고 `platform.security.service-role-preset`을 직접 설정한다.
