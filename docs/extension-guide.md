# Extension Guide

이 문서는 3계층 서비스가 `platform-security`에 자기 서비스 차이를 연결하는 방법을 설명한다.

핵심은 간단하다.

```text
2계층은 공통 흐름을 제공한다.
3계층은 서비스마다 다른 판단을 bean이나 설정으로 제공한다.
```

## 가장 자주 바꾸는 것

| 바꾸는 것 | 언제 필요한가 |
| --- | --- |
| `SecurityContextResolver` | 현재 요청의 사용자를 우리 서비스 방식으로 찾아야 할 때 |
| `InternalTokenClaimsValidator` | internal token의 issuer/audience/service id를 검증해야 할 때 |
| `RateLimiter` | 운영에서 Redis 같은 공유 저장소로 요청 횟수를 세야 할 때 |
| `RateLimitKeyResolver` | rate limit 기준을 IP가 아니라 user id 등으로 바꾸고 싶을 때 |
| `ClientIpResolver` | 특수한 proxy 환경에서 client IP 계산을 바꾸고 싶을 때 |
| `SecurityAuditPublisher` | 보안 판단 기록을 별도 저장소에 남기고 싶을 때 |
| `SecurityFailureResponseWriter` | Servlet 실패 응답 body를 서비스 표준에 맞추고 싶을 때 |
| `ReactiveSecurityFailureResponseWriter` | WebFlux 실패 응답 body를 서비스 표준에 맞추고 싶을 때 |

## 현재 사용자 연결

운영 서비스는 `SecurityContextResolver`를 제공한다.  
쉽게 말하면 “이 요청의 사용자가 누구인지 2계층에 알려주는 코드”다.

```java
@Bean
SecurityContextResolver securityContextResolver(CurrentUserResolver currentUserResolver) {
    return request -> {
        CurrentUser user = currentUserResolver.resolve(request);
        if (user == null) {
            return new SecurityContext(false, null, Set.of(), request.attributes());
        }
        return new SecurityContext(true, user.id(), user.roles(), request.attributes());
    };
}
```

local/test에서만 기본 사용자 확인 코드를 쓸 수 있다. 운영에서는 직접 제공해야 한다.

## 1계층 OSS Bean 제공 기준

3계층이 1계층 OSS 구현 bean을 제공하는 것은 허용한다.

```text
허용:
- TokenService
- SessionStore
- OidcTokenVerifier
- ApiKeyPrincipalResolver
- HmacSecretResolver
- HmacSignatureVerifier
- ServiceAccountVerifier
- RateLimiter
```

하지만 `platform-security` 내부 실행 흐름을 직접 조립하면 안 된다.

```text
금지:
- PlatformAuthenticationFacade 직접 new
- DefaultAuthenticationCapabilityResolver 직접 new
- filter 순서 직접 재구성
- auth/ip/rate-limit 흐름을 서비스마다 제각각 구성
```

## Internal Token 검증

내부 호출용 token은 “서명 검증”만으로 끝내면 부족할 수 있다.  
서비스마다 issuer, audience, service id, environment 조건이 다르기 때문이다.

그 차이는 `InternalTokenClaimsValidator`로 제공한다.

```java
@Bean
InternalTokenClaimsValidator internalTokenClaimsValidator() {
    return (principal, request) ->
            "billing-service".equals(principal.getAttribute("aud"));
}
```

## Rate Limit Key 변경

기본 요청 제한 기준을 바꾸고 싶으면 `RateLimitKeyResolver`를 제공한다.

```java
@Bean
RateLimitKeyResolver rateLimitKeyResolver() {
    return (request, context, profile) -> {
        if (context.authenticated()) {
            return "user:" + context.principal();
        }
        return "ip:" + request.clientIp();
    };
}
```

운영에서는 여러 서버가 같은 횟수를 보도록 공유 `RateLimiter`를 제공한다.

```java
@Bean
RateLimiter rateLimiter(RedisClient redisClient) {
    return new RedisBackedRateLimiter(redisClient);
}
```

`RedisBackedRateLimiter`는 예시 이름이다. 실제 Redis 기반 구현은 3계층이나 별도 공통 모듈에서 제공한다.

## OIDC / API Key / HMAC / Service Account

2계층은 인증값을 어디서 읽고 어떤 흐름에 연결할지 표준화한다.  
실제 key 조회, signature 검증, OIDC token 검증은 서비스나 1계층 구현이 제공한다.

예:

```java
@Bean
OidcTokenVerifier oidcTokenVerifier(ServiceOidcVerifier verifier) {
    return request -> verifier.verify(request.idToken(), request.nonce());
}
```

## Token / Session 발급

issuer 역할 서비스는 token/session 발급 기능을 사용할 수 있다.

하지만 로그인 성공 판단은 3계층 책임이다.

```text
3계층:
password / MFA / OAuth2 callback / 계정 상태 확인
운영 TokenService / SessionStore 제공

2계층:
발급 흐름을 표준 기능으로 연결

1계층:
실제 JWT/session 생성
```

## Public Endpoint Rate Limit

`PUBLIC` path는 로그인 없이 열려 있다.  
그래도 로그인, refresh, OAuth2 시작점은 공격 대상이므로 route limit을 둔다.

```yaml
platform:
  security:
    rate-limit:
      routes:
        - name: login
          patterns:
            - /auth/login
            - /v1/auth/login
          requests: 5
          window-seconds: 60
```

## 보안 판단 기록

보안 판단 결과를 저장하고 싶으면 `SecurityAuditPublisher`를 제공한다.

```java
@Bean
SecurityAuditPublisher securityAuditPublisher() {
    return event -> auditStore.save(event);
}
```

governance audit과 연결하려면 `platform-security-governance-bridge`를 추가한다.  
직접 `SecurityAuditPublisher` bean을 등록하면 bridge의 기본 저장 방식보다 우선한다.

## 실패 응답 형식 변경

기본 실패 응답은 아래 JSON이다.

```json
{"code":"security.auth.required","message":"..."}
```

Servlet 서비스에서 응답 포맷을 바꾸고 싶으면 `SecurityFailureResponseWriter`를 제공한다.

```java
@Bean
SecurityFailureResponseWriter securityFailureResponseWriter(ObjectMapper objectMapper) {
    return (request, response, failure) -> {
        GlobalResponse<Object> body = GlobalResponse.fail(
                failure.status(),
                failure.message(),
                failure.code()
        );

        response.setStatus(failure.status());
        response.setContentType("application/json");
        objectMapper.writeValue(response.getWriter(), body);
    };
}
```

WebFlux 서비스는 `ReactiveSecurityFailureResponseWriter`를 제공한다.

```java
@Bean
ReactiveSecurityFailureResponseWriter reactiveSecurityFailureResponseWriter(ObjectMapper objectMapper) {
    return (exchange, failure) -> {
        GlobalResponse<Object> body = GlobalResponse.fail(
                failure.status(),
                failure.message(),
                failure.code()
        );

        exchange.getResponse().setStatusCode(HttpStatus.valueOf(failure.status()));
        byte[] bytes = objectMapper.writeValueAsBytes(body);
        return exchange.getResponse()
                .writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
    };
}
```

## 추가 개발 기준

새 기능을 `platform-security`에 넣을 때는 아래 순서로 판단한다.

```text
1. 여러 서비스가 똑같이 써야 하는가?
   -> 2계층 후보

2. 특정 서비스의 업무 의미를 알아야 하는가?
   -> 3계층에 둔다

3. JWT 검증, IP rule 평가처럼 작은 기본 기능인가?
   -> 1계층에 둔다
```

주의할 점:

```text
- 2계층에 특정 서비스 이름별 if문을 넣지 않는다.
- 2계층에 password 검증, 문서 소유자 판단 같은 업무 로직을 넣지 않는다.
- 운영에서 local/test용 기본 구현을 자동으로 쓰게 만들지 않는다.
- Spring/Servlet 타입을 core 평가 엔진 안으로 밀어 넣지 않는다.
```
