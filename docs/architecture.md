# Architecture

이 문서는 `platform-security`가 어떤 계층이고, 3계층 서비스가 어떻게 써야 하는지 설명한다.

```text
1계층 auth/ip-guard/rate-limiter OSS
-> 2계층 platform-security
-> 3계층 서비스
```

## 계층 기준

여기서 말하는 계층은 `controller/service/repository`가 아니다.  
라이브러리, 플랫폼, 실제 서비스를 나누는 기준이다.

```text
1계층 = 서비스 이름을 몰라도 쓸 수 있는 기본 기능
2계층 = 여러 서비스가 같은 방식으로 쓰게 만든 보안 플랫폼
3계층 = 실제 배포되는 서비스
```

쉽게 말하면:

```text
1계층 = 재료
2계층 = 표준 조리법과 안전장치
3계층 = 실제 요리하는 곳
```

## 1계층

1계층은 작은 보안 기능을 제공하는 OSS다.

예:

```text
auth-core
auth-jwt
auth-session
auth-hybrid
auth-apikey
auth-hmac
auth-oidc
auth-service-account
ip-guard
rate-limiter
```

1계층이 하는 일:

```text
- JWT 만들기 / 검증하기
- refresh token 만들기 / 검증하기
- session 저장 / 조회 / 삭제
- API key 검증
- HMAC signature 검증
- OIDC id_token 검증
- service account 검증
- IP rule 평가
- 요청 횟수 계산
```

1계층이 하지 않는 일:

```text
- 이 endpoint가 public/admin/internal인지 판단
- 이 서비스가 gateway인지 issuer인지 판단
- 운영에서 어떤 설정을 금지할지 판단
- 여러 인증 방식을 어떤 순서로 실행할지 결정
- 서비스별 업무 권한 판단
```

## 2계층

2계층은 `platform-security`다.

2계층은 1계층 OSS를 소비한다.  
즉 auth, ip-guard, rate-limiter를 가져와 여러 서비스가 같은 방식으로 쓰도록 조립한다.

2계층이 하는 일:

```text
- starter 제공
- Spring Boot 자동 설정 제공
- 요청을 SecurityRequest로 표준화
- 현재 사용자 정보를 SecurityContext로 표준화
- URL path를 public/protected/admin/internal 보안 구역으로 분류
- Authorization, cookie, internal token 같은 인증값을 정확히 분류
- 어떤 인증 방식을 쓸지 선택
- 1계층 auth OSS 호출
- IP 제한과 요청 횟수 제한 실행
- 실패 응답을 401/403/429로 기본 정리
- 보안 판단 기록 생성
- 다음 서비스로 넘길 사용자 header 생성
- 운영에서 위험한 설정을 시작 전에 차단
- local/test용 기본 구현을 별도 모듈로 분리
```

2계층이 하지 않는 일:

```text
- password가 맞는지 판단
- 사용자가 휴면/잠김/탈퇴 상태인지 판단
- OAuth2 callback 업무 처리
- 문서 소유자 여부 판단
- 결제 가능 여부 판단
- 조직 관리자 여부 판단
- 특정 서비스 URL 하드코딩
- 업무 DB의 최종 소유
- 운영자가 관리하는 publish/revoke/history workflow 소유
```

2계층의 기준:

```text
서비스 업무 의미는 모르되,
보안 입력과 운영 기본값은 엄격하게 표준화한다.
```

## 3계층

3계층은 실제 배포되는 서비스다.

예:

```text
gateway/edge service
issuer service
resource API service
admin service
internal worker
앞으로 추가될 모든 서비스
```

3계층이 하는 일:

```text
- starter 하나 선택
- endpoint path를 public/protected/admin/internal로 선언
- 현재 요청의 사용자를 찾는 SecurityContextResolver 제공
- 운영용 RateLimiter 제공
- internal token을 쓴다면 claim 검증 코드 제공
- issuer 역할이면 운영용 TokenService / SessionStore 제공
- 사용자/조직/문서/결제 같은 업무 권한 판단
- controller/service use case 실행
- 업무 데이터와 운영 상태 소유
```

3계층이 하지 않는 일:

```text
- platform-security 내부 모듈을 직접 조립
- 서비스마다 filter 순서를 직접 조립
- 내부 호출용 사용자 header를 임의 규칙으로 생성
- 운영에서 local/test용 기본 구현에 의존
- Basic/Digest/Bearer 인증값을 임의로 섞어 해석
```

## 3계층 소비 방식

3계층은 보통 이렇게 쓴다.

```gradle
dependencies {
    implementation platform("io.github.jho951.platform:platform-security-bom:1.0.6")
    implementation "io.github.jho951.platform:platform-security-resource-server-starter"
}
```

starter는 서비스의 주 역할만 표현한다.  
한 서비스에 public/protected/admin/internal endpoint가 모두 있어도 starter를 여러 개 붙이지 않는다.

예:

```text
issuer 서비스
-> issuer-starter 하나만 사용
-> /internal/** 는 boundary.internal-paths로 선언
```

## 요청 처리 흐름

HTTP 요청은 아래 순서로 처리한다.

```text
1. Servlet/WebFlux request 수신
2. 외부에서 보내면 안 되는 X-Security-* header 제거
3. SecurityRequest 생성
4. Authorization, internal token, session cookie를 표준 attribute로 분류
5. boundary를 먼저 계산
6. SecurityContextResolver로 현재 사용자 계산
7. client type과 auth mode 계산
8. 알맞은 인증 방식 실행
9. IP 제한 실행
10. 요청 횟수 제한 실행
11. 실패하면 401/403/429 응답
12. 성공하면 다음 서비스로 넘길 사용자 header 생성
13. 보안 판단 기록 생성
14. controller로 전달
```

중요한 순서:

```text
boundary 계산
-> SecurityContextResolver
-> 인증 / IP 제한 / 요청 횟수 제한
```

internal-service 인증은 boundary와 internal token에 의존하므로 boundary가 먼저 계산되어야 한다.

## 인증값 분류 규칙

2계층은 인증값을 정확히 분류한다.

```text
Authorization: Bearer xxx
-> auth.accessToken = xxx

Authorization: Basic xxx
-> auth.accessToken = null

Authorization: Digest xxx
-> auth.accessToken = null

X-Auth-Internal-Token: xxx
-> auth.internalToken = xxx

Session cookie
-> auth.sessionId = xxx
```

다른 방식을 지원해야 하면 access token에 섞지 않고 별도 값으로 추가한다.

```text
Basic credential
-> auth.basicCredential

API key
-> auth.apiKeyId / auth.apiKeySecret

HMAC
-> auth.hmac.*

Service account
-> auth.serviceAccount*

OIDC
-> auth.oidc.*
```

이 규칙은 운영 정책이 아니라 프로토콜 의미를 지키는 것이다.

## Starter 선택

| Starter | 쓰는 서비스 |
| --- | --- |
| `platform-security-edge-starter` | 외부 요청이 처음 들어오는 gateway/edge |
| `platform-security-issuer-starter` | token/session을 발급하는 서비스 |
| `platform-security-resource-server-starter` | 일반 API를 제공하는 서비스 |
| `platform-security-internal-service-starter` | 서비스 전체가 내부 호출 전용인 서비스 |
| `platform-security-starter` | 역할을 설정으로 직접 정하는 서비스 |

## 3계층 연결점

3계층이 자주 제공하는 bean:

```text
SecurityContextResolver
InternalTokenClaimsValidator
RateLimitKeyResolver
ClientIpResolver
SecurityAuditPublisher
PlatformSecurityCustomizer
PlatformIpRuleSourceFactory
```

3계층은 내부 구현 class를 직접 new 하지 않고, 이 공개 계약과 `platform.security.*` 설정으로 차이를 표현한다.

## 1계층 OSS Bean 제공 기준

3계층이 1계층 OSS 구현 bean을 제공하는 것은 허용한다.

```text
허용:
- TokenService bean 제공
- SessionStore bean 제공
- OidcTokenVerifier bean 제공
- HmacSecretResolver bean 제공
- ServiceAccountVerifier bean 제공
- RateLimiter bean 제공
```

하지만 3계층이 2계층 실행 흐름을 직접 조립하거나 우회하면 안 된다.

```text
금지:
- PlatformAuthenticationFacade 직접 new
- DefaultAuthenticationCapabilityResolver 직접 new
- platform-security filter 순서 직접 조립
- auth/ip/rate-limit 흐름을 서비스마다 제각각 재구성
```

## Local/Test

local/test용 기본 구현은 `platform-security-local-support`에 있다.

```gradle
dependencies {
    testImplementation "io.github.jho951.platform:platform-security-local-support"
}
```

```yaml
platform:
  security:
    local-support:
      enabled: true
```

제공하는 것:

```text
- local JwtTokenService
- SimpleSessionStore
- local InternalTokenClaimsValidator
- InMemoryRateLimiter
- local/test용 기본 SecurityContextResolver
```

운영에서는 local-support에 의존하지 않는다.

## Audit

보안 판단 기록 흐름:

```text
SecurityEvaluationResult
-> SecurityAuditEvent
-> SecurityAuditPublisher
-> governance bridge 또는 직접 구현한 저장소
```

기록 양은 mode로 조절한다.

```text
DENY_ONLY
DENY_AND_ADMIN
INTERNAL_AND_ADMIN
ALL
```

## Policy Config

정책 읽기 계약은 `platform-policy-api`가 소유한다.

```text
platform-policy-api
-> PolicyConfigSource
-> PolicySnapshot
```

`platform-security`는 이 계약을 소비해서 IP rule 같은 값을 읽는다.  
governance가 정책을 관리하더라도 security는 governance 관리 API를 직접 보지 않는다.

```text
platform-governance
-> 정책 publish / revoke / history / audit owner

platform-security
-> platform-policy-api를 통해 정책 값 읽기
```

## Outbound

다른 서비스로 호출할 때 현재 사용자 정보를 넘기는 흐름이다.

```text
inbound SecurityContext
-> 다음 서비스로 보낼 표준 header
-> platform-security-client
-> RestTemplate / RestClient / WebClient / Feign
-> 다음 서비스
```

3계층은 header 이름을 직접 조립하지 않고 `platform-security-client`를 사용한다.

신뢰 기준:

```text
외부 요청이 보낸 X-Security-* header
-> 신뢰하지 않음
-> filter가 먼저 제거

platform-security filter가 만든 X-Security-* header
-> 내부 호출에서만 신뢰

서비스가 임의로 만든 X-Security-* header
-> 신뢰하지 않는 것이 원칙
```

## 운영 안전장치

운영으로 보는 조건:

```text
active Spring profile: prod, production, live
또는
platform.security.operational-policy.production=true
```

운영에서 시작을 막는 것:

```text
- SecurityContextResolver 없음
- auth disabled
- auth.default-mode=NONE
- local/test용 기본 사용자 확인 기능 사용
- dev JWT secret
- local TokenService
- local SessionStore
- local InternalTokenClaimsValidator
- RateLimiter 없음
- in-memory RateLimiter
- IP guard disabled
- trust-proxy=true인데 trusted proxy CIDR 없음
- admin/internal IP rule 비어 있음
- rate limit disabled
- 0 이하 rate limit quota
```

## 좋은 사용 방식

```text
- BOM과 starter 하나를 사용한다.
- endpoint 차이는 boundary 설정으로 표현한다.
- 운영용 SecurityContextResolver를 제공한다.
- 운영용 RateLimiter를 제공한다.
- internal endpoint가 있으면 InternalTokenClaimsValidator를 제공한다.
- 업무 권한 판단은 3계층 service/controller에서 한다.
- audit/outbound는 2계층 표준 계약을 사용한다.
```

## 나쁜 사용 방식

```text
- 여러 role starter를 동시에 붙인다.
- platform-security 내부 모듈을 직접 조립한다.
- 2계층에 서비스 이름별 if문을 추가한다.
- 로그인 성공 조건을 2계층으로 밀어 넣는다.
- 문서 소유자/조직 관리자 판단을 2계층에 넣는다.
- Authorization header 전체를 access token으로 간주한다.
- 운영에서 local/test용 기본 구현에 의존한다.
```

## 최종 판단 기준

```text
작은 보안 기본 기능인가?
-> 1계층

여러 서비스가 같은 방식으로 써야 하는 보안 흐름인가?
-> 2계층

서비스 데이터나 업무 의미를 알아야 판단 가능한가?
-> 3계층
```
