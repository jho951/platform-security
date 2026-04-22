# platform-security

Spring Boot 서비스가 인증, IP 제한, rate limit 보안 흐름을 같은 방식으로 쓰도록 조립하는 2계층 보안 플랫폼이다.

공개 auth 계약은 `PlatformAuthenticatedPrincipal`, `PlatformOAuth2UserIdentity` 같은 platform-owned 타입을 사용하고, rate limit policy는 `PlatformRateLimitAdapter` decision 계약만 본다. gateway 통합이 필요한 경우 `platform-security-hybrid-web-adapter`의 `PlatformSecurityGatewayIntegration`이 공식 조립 표면이다.

## Documentation

- [문서 인덱스](docs/README.md)

## Verification

```bash
./gradlew test
```
