# Extension Guide

3계층 서비스는 `platform-security` 내부 흐름을 직접 조립하지 않는다. 서비스마다 다른 판단만 bean이나 설정으로 제공한다.

## Common Extension Points

| 바꾸는 것 | 언제 필요한가 |
| --- | --- |
| `SecurityContextResolver` | 현재 요청의 사용자를 서비스 방식으로 찾아야 할 때 |
| `InternalTokenClaimsValidator` | internal token의 issuer/audience/service id를 검증해야 할 때 |
| `PlatformRateLimitPort` | 운영에서 Redis 같은 공유 저장소 기반 rate limit 판단을 platform 계약으로 연결해야 할 때 |
| `RateLimitKeyResolver` | rate limit 기준을 IP가 아니라 user id 등으로 바꾸고 싶을 때 |
| `ClientIpResolver` | 특수한 proxy 환경에서 client IP 계산을 바꾸고 싶을 때 |
| `SecurityAuditPublisher` | 보안 판단 기록을 별도 저장소에 남기고 싶을 때 |
| `SecurityFailureResponseWriter` | Servlet 실패 응답 body를 서비스 표준에 맞추고 싶을 때 |
| `ReactiveSecurityFailureResponseWriter` | WebFlux 실패 응답 body를 서비스 표준에 맞추고 싶을 때 |

## Current User

운영 서비스는 `SecurityContextResolver`를 제공한다.

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

## Production Beans

3계층이 운영 구현을 제공하는 것은 허용한다.

```text
PlatformTokenIssuerPort
PlatformSessionIssuerPort
PlatformSessionSupportFactory
PlatformRateLimitPort
OidcTokenVerifier
ApiKeyPrincipalResolver
HmacSecretResolver
HmacSignatureVerifier
ServiceAccountVerifier
PlatformRateLimitPort
```

strict 기준에서 서비스가 직접 봐야 하는 운영 bean은 platform port와 runtime hook이다. raw auth provider 같은 외부 보안 SPI는 adapter layer 내부에서만 연결하는 것이 목표다. `platform-security`의 공개 auth 계약은 platform-owned runtime view와 port를 사용하고, adapter가 필요할 때만 raw SPI를 뒤에서 감싼다.

단, `platform-security` 내부 흐름을 직접 조립하지 않는다.

```text
금지:
- PlatformAuthenticationFacade 직접 new
- DefaultAuthenticationCapabilityResolver 직접 new
- filter 순서 직접 재구성
- auth/ip/rate-limit 흐름을 서비스마다 제각각 구성
```

## Internal Token

내부 호출용 token은 서명 검증만으로 부족할 수 있다. 서비스마다 issuer, audience, service id, environment 조건이 다르기 때문이다.

```java
@Bean
InternalTokenClaimsValidator internalTokenClaimsValidator() {
    return (principal, request) ->
            "billing-service".equals(principal.attributes().get("aud"));
}
```

## Rate Limit

운영에서는 여러 서버가 같은 횟수를 보도록 공유 저장소 기반 구현을 `PlatformRateLimitPort`로 감싼다.

```java
@Bean
PlatformRateLimitPort platformRateLimitPort(StringRedisTemplate redisTemplate) {
    return new DefaultPlatformRateLimitAdapter(
        new RedisFixedWindowRateLimiter(redisTemplate, "platform-security:rate-limit:", Clock.systemUTC())
    );
}
```

raw `RateLimiter`를 직접 policy로 넘기지 않는다. 필요하면 adapter 내부 구현에서만 사용한다. 서비스-facing contract는 `PlatformRateLimitPort`로 닫는다.

기본 요청 제한 기준을 바꾸고 싶으면 `RateLimitKeyResolver`를 제공한다.

```java
@Bean
RateLimitKeyResolver rateLimitKeyResolver() {
    return (request, context, profile) ->
            context.authenticated() ? "user:" + context.principal() : "ip:" + request.clientIp();
}
```

## OIDC / API Key / HMAC / Service Account

2계층은 인증값을 어디서 읽고 어떤 흐름에 연결할지 표준화한다. 실제 key 조회, signature 검증, OIDC token 검증은 서비스나 외부 보안 구현이 제공하되, 1계층 타입 노출은 adapter layer로 제한하는 것이 목표다.

```java
@Bean
OidcTokenVerifier oidcTokenVerifier(ServiceOidcVerifier verifier) {
    return request -> verifier.verify(request.idToken(), request.nonce());
}
```

## Token / Session Issuance

`issuer` preset 서비스는 token/session 발급 기능을 사용할 수 있다. 로그인 성공 판단과 계정 상태 검증은 3계층 책임이다.

```text
3계층:
password / MFA / OAuth2 callback / 계정 상태 확인
운영 platform port 제공 또는 adapter module 선택

2계층:
발급 흐름을 platform-owned runtime/port/session-support factory 뒤로 연결
```

## Gateway Hybrid Integration

gateway가 hybrid mode에서 ingress를 직접 조립해야 하면 `platform-security-hybrid-web-adapter`를 붙인다. Servlet gateway는 `PlatformSecurityGatewayIntegration`, WebFlux gateway는 `PlatformSecurityReactiveGatewayIntegration` bean을 사용한다.

```text
PlatformSecurityGatewayIntegration
-> SecurityIngressAdapter
-> PlatformSecurityServletFilter
-> gateway header filter
-> SecurityFailureResponseWriter
-> SecurityAuditPublisher

PlatformSecurityReactiveGatewayIntegration
-> SecurityIngressAdapter
-> PlatformSecurityWebFilter
-> gateway header web filter
-> ReactiveSecurityFailureResponseWriter
-> SecurityAuditPublisher
```

## Audit

보안 판단 결과를 저장하고 싶으면 `SecurityAuditPublisher`를 제공한다.

```java
@Bean
SecurityAuditPublisher securityAuditPublisher() {
    return event -> auditStore.save(event);
}
```

governance audit과 연결하려면 `platform-integrations` repository에서 별도 artifact인 `platform-security-governance-bridge`를 추가한다. 직접 `SecurityAuditPublisher` bean을 등록하면 bridge의 기본 bean보다 우선한다.

## Failure Response

기본 실패 응답을 서비스 표준 body로 바꾸고 싶으면 writer bean을 제공한다.

```java
@Bean
SecurityFailureResponseWriter securityFailureResponseWriter(ObjectMapper objectMapper) {
    return (request, response, failure) -> {
        response.setStatus(failure.status());
        response.setContentType("application/json");
        objectMapper.writeValue(response.getWriter(), GlobalResponse.fail(failure));
    };
}
```

WebFlux 서비스는 `ReactiveSecurityFailureResponseWriter`를 제공한다.

## Development Rule

새 기능을 넣을 때는 아래 기준으로 나눈다.

```text
여러 서비스가 같은 방식으로 써야 하는 보안 흐름
-> 2계층 후보

특정 서비스의 업무 의미를 알아야 하는 판단
-> 3계층에 둔다

JWT 검증, IP rule 평가처럼 작은 기본 기능
-> platform-security 내부 의존성 또는 별도 라이브러리 후보
```
