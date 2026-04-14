# platform-security

## 제공 범위

### 책임

- boundary / client type / auth mode 공통 모델
- 요청별 capability 선택과 정책 평가
- auth, ip-guard, rate-limiter 조립
- 실패 응답 표준화
- downstream 신원 전달 표준화
- Servlet / WebFlux 진입점
- Spring Boot auto-configuration
- 운영용 override point

### 책임 X

- 로그인 / 회원가입 / 토큰 발급 비즈니스
- 사용자 계정 조회 비즈니스
- 서비스별 관리자 role 이름
- 특정 서비스 URL 하드코딩
- 특정 서비스 Redis key 규칙
- 1계층 OSS 내부 구현 재정의

## 빠른 사용

운영 서비스는 반드시 `SecurityContextResolver` bean을 직접 제공한다.
`platform.security.auth.dev-fallback.enabled=true`는 local/test 전용 opt-in이다.

```gradle
dependencies {
    implementation platform("io.github.jho951.platform:platform-security-bom:1.0.3")
    implementation "io.github.jho951.platform:platform-security-starter"
}
```

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

## 빌드

```bash
./gradlew test
```

## (문서)[docs/README.md]
