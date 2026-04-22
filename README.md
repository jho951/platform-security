# platform-security

Spring Boot 서비스가 인증, IP 제한, rate limit 보안 흐름을 같은 방식으로 쓰도록 조립하는 2계층 보안 플랫폼이다.

공개 auth 계약은 `PlatformIssueTokenCommand`, `PlatformIssueSessionCommand`, `PlatformIssuedToken`, `PlatformSessionView` 같은 platform-owned runtime view와 port만 사용하고, rate limit policy는 `PlatformRateLimitPort` decision 계약만 본다. `com.auth.*`, raw `RateLimiter` 같은 1계층 타입은 adapter layer에서만 남겨야 한다. gateway 통합이 필요한 경우 `platform-security-hybrid-web-adapter`가 Servlet용 `PlatformSecurityGatewayIntegration`과 WebFlux용 `PlatformSecurityReactiveGatewayIntegration`을 공식 조립 표면으로 제공한다.

## Documentation

- [문서 인덱스](docs/README.md)

## Verification

```bash
./gradlew test
```
