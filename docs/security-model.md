# Security Model

`platform-security`는 요청 단위로 boundary와 profile을 해석하고, 그 결과에 따라 authentication, ip-guard, rate limit을 조립해 평가한다.

## 런타임 모델

- `SecurityRequest`: path, method, client IP, 인증 입력, 요청 시각을 담는다.
- `SecurityContext`: 인증 결과와 principal, roles, attributes를 담는다.
- `ResolvedSecurityProfile`: boundary, client type, auth mode를 담는다.
- `SecurityEvaluationResult`: profile과 최종 verdict를 함께 반환한다.

## 평가 순서

1. header scrub과 client IP 해석
2. boundary 결정
3. client type 결정
4. auth mode 결정
5. profile에 따른 auth 실행
6. profile에 따른 ip-guard 실행
7. profile에 따른 rate limit 실행
8. downstream identity propagation
9. 모두 통과하면 allow

## 결과

- `ALLOW`
- `DENY`

## Boundary

- `PUBLIC`: 인증 없이 접근 가능한 경계다. 기본 rate limit은 건너뛴다.
- `PROTECTED`: 인증된 사용자 중심 경계다.
- `ADMIN`: 관리자 경계다. IP allow CIDR 적용 대상이다.
- `INTERNAL`: 내부 서비스 경계다. internal quota와 internal token 정책 적용 대상이다.

## Client Type

- `BROWSER`: 세션 또는 hybrid 인증을 주로 사용한다.
- `EXTERNAL_API`: bearer/JWT 인증을 주로 사용한다.
- `INTERNAL_SERVICE`: 내부 서비스 인증과 internal rate limit profile을 사용한다.
- `ADMIN_CONSOLE`: admin boundary와 함께 IP 정책을 받는다.

## Auth Mode

- `NONE`: 인증 capability를 실행하지 않는다.
- `JWT`: bearer/access token을 검증한다.
- `SESSION`: session id를 검증한다.
- `HYBRID`: JWT와 session을 함께 받아 조합한다.
- `API_KEY`: API key credential을 검증한다.
- `HMAC`: 요청 서명 credential을 검증한다.
- `OIDC`: 3계층이 제공한 `OidcTokenVerifier`로 OIDC ID token을 검증한다.
- `SERVICE_ACCOUNT`: service account credential을 검증한다.

`allowSessionForBrowser`, `allowBearerForApi`, `allowApiKeyForApi`, `allowHmacForApi`, `allowOidcForApi`, `serviceAccountEnabled`, `internalTokenEnabled` 값은 auth mode 선택에 반영된다.

## Header Contract

`trust-proxy=true`이면 remote address가 `ip-guard.trusted-proxy-cidrs`에 포함될 때만 `X-Forwarded-For`를 client IP로 사용한다. 운영에서는 trusted proxy CIDR를 비워 두지 않는다.

인증 입력으로 허용하는 값:

- `Authorization`
- cookie 기반 access token
- cookie 기반 session id
- `X-Auth-Session-Id` 같은 명시적 session 입력
- `X-Auth-Api-Key-Id`, `X-Auth-Api-Key-Secret`
- `X-Auth-Hmac-Key-Id`, `X-Auth-Hmac-Signature`, `X-Auth-Hmac-Timestamp`, `X-Auth-Hmac-Signed-Headers`
- `X-Auth-Oidc-Id-Token`, `X-Auth-Oidc-Nonce`
- `X-Auth-Service-Account-Id`, `X-Auth-Service-Account-Secret`

ingress에서 신뢰하지 않는 downstream propagation 값:

- `X-Security-*`
- `X-Auth-Roles`
- `X-Security-Principal`
- `X-Security-Client-Type`
- `X-Security-Auth-Mode`

## 기준

- 정책 실패는 401, 403, 429 중 하나로 표준화한다.
- boundary/profile은 3계층 application이 공급한다.
- 서비스별 URL, Redis key, role 이름은 여기서 정의하지 않는다.
- 운영에서는 서비스가 `SecurityContextResolver`를 직접 제공한다.
- dev fallback resolver는 local/test opt-in이다.
- OIDC provider별 login flow와 ID token verifier 구현은 3계층 또는 1계층 구현 책임이다.
- 운영 rate limit은 공유 `RateLimiter` bean으로 적용한다. 기본 in-memory 구현은 local/test용이며 production에서는 fail-fast 된다.
- governance bridge를 쓰면 최종 security verdict가 governance audit entry로 기록된다.
