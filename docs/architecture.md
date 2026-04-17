# Architecture

## 계층 책임

- 공통 정책 모델
- 공통 실행 체인
- 공통 starter와 auto-configuration
- 공통 interface/SPI
- 안전한 기본값
- 운영 fail-fast 규칙
- 역할별 preset
- 서비스별 선언 포인트

## 설계 원칙

- 서비스 이름과 도메인 규칙을 몰라야 한다.
- 기본값을 제공하되 서비스에 override를 허용해야 한다.
- 조립 계층이지 업무 계층이 아니다.
- 내부도 core, runtime, autoconfigure, starter로 나눈다.

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

## 2계층/3계층 경계

2계층은 보안 운영 프레임을 가진다. 즉 요청을 어떤 boundary로 볼지, 어떤 인증 모드와 client type을 적용할지, IP guard/rate limit/downstream identity를 어떤 순서로 실행할지, 운영에서 어떤 설정을 fail-fast 할지를 표준화한다.

3계층은 서비스의 의미를 가진다. 서비스는 role starter 하나를 소비하고, `SecurityContextResolver` 같은 공개 SPI와 설정으로 차이를 선언한다. 문서 소유자, 사용자 본인 여부, 워크스페이스 관리자 여부처럼 도메인 데이터를 알아야 하는 판단은 3계층에 둔다.

따라서 3계층 서비스는 내부 모듈을 직접 조립하지 않는다. 기본 소비 단위는 `platform-security-bom`과 role starter 하나이며, endpoint별 차이는 `boundary.*`, `rate-limit.routes[]`, override bean으로 표현한다.

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
10. governance bridge가 있으면 평가 결과를 audit entry로 기록한다.

## 운영 안전성

운영정책은 `OperationalSecurityPolicyEnforcer`가 직접 강제한다.

운영으로 판단하는 조건:

- active profile이 `prod`
- 또는 `platform.security.operational-policy.production=true`

운영에서 금지되는 것:

- `SecurityContextResolver` 누락
- dev fallback resolver 사용
- `auth.default-mode=NONE`
- auth, IP guard, rate limit 비활성화
- 비어 있는 admin/internal IP rule
- `trust-proxy=true`인데 trusted proxy CIDR 누락
- 운영 공유 `RateLimiter` bean 누락
- 플랫폼 기본 token service/session store/internal token allow-all validator 사용
- in-memory `RateLimiter` 사용
- dev JWT secret 사용
- 0 이하 rate limit quota

## 서비스 적용 방식

3계층 서비스는 `platform-security-bom`과 starter 하나를 선택한다.

역할별 starter는 서비스의 주 역할(primary role)을 표현한다. 서비스 안에 여러 boundary가 있을 수 있지만 starter는 하나만 선택하고, endpoint별 차이는 `boundary.*`, `rate-limit.routes[]`, override bean으로 선언한다.

역할이 명확하지 않으면 일반 `platform-security-starter`를 사용하고 `platform.security.service-role-preset`을 직접 설정한다.
