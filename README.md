# platform-security

Spring Boot 서비스가 인증, IP 제한, rate limit 보안 흐름을 같은 방식으로 쓰도록 조립하는 2계층 보안 플랫폼이다.

공개 auth 계약은 `PlatformIssueTokenCommand`, `PlatformIssueSessionCommand`, `PlatformIssuedToken`, `PlatformSessionView` 같은 platform-owned runtime view와 port만 사용하고, rate limit policy는 `PlatformRateLimitPort` decision 계약만 본다. `com.auth.*`, raw `RateLimiter` 같은 1계층 타입은 adapter layer에서만 남겨야 한다.

gateway 통합이 필요한 경우 `platform-security-hybrid-web-adapter`가 Servlet용 `PlatformSecurityGatewayIntegration`과 WebFlux용 `PlatformSecurityReactiveGatewayIntegration`을 공식 조립 표면으로 제공한다. gateway/edge 서비스는 `SecurityIngressAdapter`나 내부 filter bean graph를 직접 재조립하지 않고 `HybridSecurityRuntime`, `HybridRouteSecurityPolicy`, `HybridFailureResponseContract`, `HybridHeaderAuthenticationAdapter` 같은 platform-owned runtime surface만 소비하는 것을 기본으로 한다.

selection mode 기본 조립은 ordered `SecurityPolicy` bean을 additive하게 수집하므로, 서비스가 policy 하나를 더 붙이기 위해 `SecurityPolicyService` 전체를 service-owned 구현으로 다시 만들 필요가 없다. internal 경계는 dedicated internal token/JWT path로 닫고, 서비스 filter나 secret header shim 같은 legacy compat 경로는 두지 않는다.

다른 서비스 호출에 security header propagation이 필요하면 `platform-security-client`를 공식 add-on으로 사용한다. 3계층은 header 이름이나 interceptor/filter를 직접 다시 만들지 않고, `platform-security-client`가 제공하는 outbound propagation surface만 소비하는 것을 기본으로 한다.

## Documentation

- [문서 인덱스](docs/README.md)

## Verification

```bash
./gradlew check
```

`check`는 starter surface 검증과 sample consumer smoke test까지 함께 실행한다.
