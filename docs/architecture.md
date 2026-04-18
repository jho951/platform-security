# Architecture

`platform-security`는 Spring Boot 서비스가 같은 보안 흐름을 쓰도록 조립하는 2계층 모듈이다.

```text
platform-security -> 3계층 서비스
```

## Design Rule

사용 진입점은 `platform-security-starter` 하나다. 서비스별 차이는 `platform.security.service-role-preset`과 세부 설정으로 표현한다.

```text
역할 기반 starter 분리
-> 하지 않는다

의존성 기반 내부 모듈 분리
-> 유지한다
```

서비스 역할마다 artifact를 나누지 않는 이유는 서비스가 늘어날수록 선택지가 복잡해지기 때문이다. 대신 `edge`, `issuer`, `api-server`, `internal-service` preset을 설정으로 선택한다.

내부 모듈은 auth, IP guard, rate limit, Servlet/WebFlux, Spring Boot auto-configuration처럼 실제 의존성 경계가 있을 때만 나눈다.

## 2계층 책임

`platform-security`가 하는 일:

```text
- Spring Boot 자동 설정 제공
- 요청을 SecurityRequest로 표준화
- 현재 사용자 정보를 SecurityContext로 표준화
- URL path를 public/protected/admin/internal boundary로 분류
- Authorization, cookie, internal token을 의미대로 분류
- 인증 방식 선택
- IP 제한과 요청 횟수 제한 실행
- 401/403/429 실패 응답 기본 처리
- 보안 판단 기록 생성
- 내부 호출용 사용자 header 생성
- 운영 위험 설정을 부팅 시점에 차단
```

`platform-security`가 하지 않는 일:

```text
- password / MFA 검증
- 사용자 휴면/잠김/탈퇴 판단
- OAuth2 callback 업무 처리
- 문서 소유자 판단
- 결제 가능 여부 판단
- 조직 관리자 판단
- 특정 서비스 URL 하드코딩
- 업무 DB 소유
```

## Request Flow

```text
1. Servlet/WebFlux request 수신
2. 외부에서 온 X-Security-* header 제거
3. SecurityRequest 생성
4. 인증값을 표준 attribute로 분류
5. path boundary 계산
6. SecurityContextResolver로 현재 사용자 계산
7. client type과 auth mode 계산
8. 인증 실행
9. admin/internal IP 제한 실행
10. rate limit 실행
11. 실패하면 401/403/429 응답
12. 성공하면 controller로 전달
13. 필요한 경우 outbound 사용자 header 생성
14. 보안 판단 기록 생성
```

boundary는 먼저 계산한다. internal 요청은 boundary를 알아야 internal token 검증을 선택할 수 있다.

## Credential Classification

인증값은 막기 전에 먼저 정확히 분류한다.

```text
Authorization: Bearer xxx
-> auth.accessToken

Authorization: Basic xxx
-> access token으로 사용하지 않음

Authorization: Digest xxx
-> access token으로 사용하지 않음

X-Auth-Internal-Token: xxx
-> auth.internalToken

Session cookie
-> auth.sessionId
```

Basic, API key, HMAC, OIDC, service account를 지원해야 하면 access token에 섞지 않고 각각 별도 attribute로 다룬다.

## Extension Points

3계층은 내부 구현 class를 직접 조립하지 않는다. 공개 bean과 `platform.security.*` 설정으로 차이를 표현한다.

자주 제공하는 bean:

```text
SecurityContextResolver
InternalTokenClaimsValidator
RateLimiter
RateLimitKeyResolver
ClientIpResolver
SecurityAuditPublisher
SecurityFailureResponseWriter
ReactiveSecurityFailureResponseWriter
PlatformSecurityCustomizer
PlatformIpRuleSourceFactory
```

허용되는 외부 보안 구현 bean:

```text
TokenService
SessionStore
OidcTokenVerifier
ApiKeyPrincipalResolver
HmacSecretResolver
HmacSignatureVerifier
ServiceAccountVerifier
RateLimiter
```

금지되는 사용 방식:

```text
PlatformAuthenticationFacade 직접 new
DefaultAuthenticationCapabilityResolver 직접 new
platform-security filter 순서 직접 조립
auth/ip/rate-limit 흐름을 서비스마다 재구성
```

## Optional Integrations

`platform-security-client`는 내부 호출 시 `SecurityContext`를 표준 header로 전달할 때 쓴다.

`platform-security-governance-bridge`는 `platform-security` release에 포함되지 않는다. security audit event를 governance audit으로 보낼 때만 `platform-integrations` repository에서 별도 artifact로 추가한다.

`platform-security-policyconfig-bridge`는 IP rule 같은 값을 외부 policy config에서 읽고 싶을 때만 추가한다.

`platform-security-local-support`는 local/test 전용 기본 구현이다. 운영 `implementation`에 넣지 않는다.
