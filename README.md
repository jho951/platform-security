# platform-security

`platform-security`는 3계층 서비스가 공통 보안 운영 규칙을 안전하게 소비하도록 만드는 2계층 플랫폼이다.

이 프로젝트는 서비스별 인증/인가 비즈니스를 대신 구현하지 않는다. 대신 요청 진입점에서 반복되는 보안 프레임을 표준화한다.

## 제공하는 것

- 공통 보안 모델: boundary, client type, auth mode, evaluation result
- 공통 실행 체인: authentication, IP guard, rate limit, downstream identity propagation
- Spring Boot auto-configuration
- 역할별 starter와 preset
- 운영 fail-fast 정책
- 서비스별 override point

## 제공하지 않는 것

- 로그인, 회원가입, 토큰 발급 비즈니스
- 사용자/문서/블록 같은 도메인 권한 판단
- 특정 서비스 URL, role 이름, Redis key 규칙
- 특정 서비스만 쓰는 예외 정책
- 1계층 OSS 내부 구현 재정의

## 빠른 사용

서비스는 BOM과 starter 하나를 사용한다.

```gradle
dependencies {
    implementation platform("io.github.jho951.platform:platform-security-bom:1.0.4")
    implementation "io.github.jho951.platform:platform-security-resource-server-starter"
}
```

역할별 starter:

- `platform-security-edge-starter`
- `platform-security-issuer-starter`
- `platform-security-resource-server-starter`
- `platform-security-internal-service-starter`

운영에서는 `SecurityContextResolver` bean을 직접 제공한다.

```java
@Bean
SecurityContextResolver securityContextResolver(
        TokenService tokenService,
        SessionStore sessionStore,
        SessionPrincipalMapper sessionPrincipalMapper
) {
    return PlatformSecurityContextResolvers.hybrid(tokenService, sessionStore, sessionPrincipalMapper);
}
```

## 문서

- [문서 지도](docs/README.md)
- [빠른 시작](docs/quickstart.md)
- [아키텍처](docs/architecture.md)
- [설정 레퍼런스](docs/configuration.md)
- [모듈 가이드](docs/modules.md)

## 검증

```bash
./gradlew test
```
