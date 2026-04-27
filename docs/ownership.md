# Ownership

`platform-security`는 인증 경계, route taxonomy, credential 해석, internal auth, rate-limit 진입 계약을 소유하는 2계층 core runtime이다.

## 2계층이 소유하는 것

- `PlatformSecurityProperties`와 `service-role-preset`
- `SecurityPolicy`, `SecurityPolicyService`, boundary evaluation
- `SecurityContextResolver`를 포함한 공식 인증 해석 surface
- `PlatformTokenIssuerPort`, `PlatformSessionIssuerPort`, `PlatformRateLimitPort`
- internal token/JWT 경계와 hybrid web adapter
- starter, auto-configuration, bridge starter, sample consumer

## 3계층이 소유하는 것

- 로그인 성공/실패 business meaning
- 계정 상태 판단, domain authorization, 도메인 권한 판정, resource ownership 같은 business authorization
- token/session 저장소의 운영 선택
- issuer role 서비스의 raw auth bean 제공 여부
- 서비스별 route 값과 필요한 optional add-on 선택

## Stage-5 규칙

- 서비스는 `platform-security-starter`를 기본 진입점으로 사용한다.
- raw auth bean이나 raw `RateLimiter`를 그대로 써야 할 때만 공식 bridge starter를 사용한다.
- 서비스는 표준 경계를 위해 service-owned security filter graph를 다시 조립하지 않는다.
- internal auth는 dedicated internal token path를 사용하고, legacy secret header shim을 서비스가 직접 유지하지 않는다.
- rate limit 확장은 `PlatformRateLimitPort` 뒤에서 처리하고, raw limiter 타입은 adapter layer 바깥 compile surface로 새지 않게 둔다.

## 두지 않을 것

- service-owned request-attribute compat filter
- service-owned internal auth bridge
- `auth-core`, `auth-jwt`, `rate-limiter-spi` 같은 raw 1계층 타입의 3계층 compile 의존
- 표준 boundary/ip/rate-limit 동작을 다시 구현한 service-local starter

## 공식 확장 표면

- `SecurityContextResolver`
- ordered `SecurityPolicy` bean
- `SecurityRequestAttributeContributor`
- `PlatformTokenIssuerPort`
- `PlatformSessionIssuerPort`
- `PlatformRateLimitPort`
- `SecurityFailureResponseWriter`

## 품질 기준

기본 검증은 `./gradlew check`다.
이 명령은 published surface 검증, starter contract 검증, sample consumer smoke test를 함께 실행한다.
