# platform-security

`platform-security`는 1계층 OSS 보안 기능을 서비스 요청 흐름에 맞게 선택하고 조립하는 2계층 내부 보안 플랫폼이다.
1계층 `auth`, `ip-guard`, `rate-limiter`의 published artifact를 exact version으로 소비하고, Spring Boot 서비스가 바로 붙일 수 있는 보안 진입점을 제공한다.

이 레포와 산출물은 내부 비공개 플랫폼이다. 외부 공개 OSS는 1계층 모듈이고, `platform-security`는 내부 서비스 공통 조립 계층이다.

## 내부 좌표

- `io.github.jho951.platform:platform-security-bom`
- `io.github.jho951.platform:platform-security-policy`
- `io.github.jho951.platform:platform-security-auth`
- `io.github.jho951.platform:platform-security-ip`
- `io.github.jho951.platform:platform-security-rate-limit`
- `io.github.jho951.platform:platform-security-web`
- `io.github.jho951.platform:platform-security-autoconfigure`
- `io.github.jho951.platform:platform-security-starter`
- `io.github.jho951.platform:platform-security-test-support`

`platform-security-api`와 `platform-security-core`는 내부 지원층이다. 서비스가 직접 바라보는 기본 진입점은 `platform-security-starter`다.

## 무엇을 제공하나

- boundary / client type / auth mode 공통 모델
- 요청별 capability 선택 엔진
- 경계 분류
- 정책 프로필 선택
- client IP 해석
- auth 수행
- ip-guard 판정
- rate-limiter 판정
- 실패 응답 표준화
- downstream 신원 전달 표준화
- security integration API 제공
- Servlet / WebFlux 진입점 제공
- Spring Boot auto-configuration
- 운영용 override point

## 무엇을 제공하지 않나

- 로그인 / 회원가입 / 토큰 발급 비즈니스
- 사용자 계정 조회 비즈니스
- 서비스별 관리자 role 이름
- 특정 서비스 URL 하드코딩
- 특정 서비스 Redis key 규칙
- 1계층 OSS 내부 구현 재정의

## 빠른 사용법

서비스는 BOM과 starter를 사용한다.

private GitHub Packages를 읽기 위해 먼저 credential을 준비한다.

```bash
export GITHUB_ACTOR=jho951
export GITHUB_TOKEN=<read:packages 권한이 있는 PAT>
```

```gradle
repositories {
    mavenCentral()
    maven {
        url = uri("https://maven.pkg.github.com/jho951/platform-security")
        credentials {
            username = findProperty("githubPackagesUsername") ?: System.getenv("GITHUB_ACTOR")
            password = findProperty("githubPackagesToken") ?: System.getenv("GITHUB_TOKEN")
        }
    }
}

dependencies {
    implementation platform("io.github.jho951.platform:platform-security-bom:1.0.2")
    implementation "io.github.jho951.platform:platform-security-starter"
}
```

운영 서비스는 반드시 `SecurityContextResolver` bean을 직접 제공한다. `platform.security.auth.dev-fallback.enabled=true`는 local/test 전용 opt-in이다.

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

## 모듈

- `platform-security-bom`
- `platform-security-policy`
- `platform-security-auth`
- `platform-security-ip`
- `platform-security-rate-limit`
- `platform-security-web`
- `platform-security-autoconfigure`
- `platform-security-starter`  # thin dependency aggregator
- `platform-security-test-support`
- 내부 호환 모듈(공개 표면 아님): `platform-security-api`, `platform-security-core`

## 핵심 정책

- 1계층 OSS는 공개 배포본으로 소비한다.
- 2계층 `platform-security`는 내부 비공개 플랫폼 레이어로 유지한다.
- 2계층은 외부 공개 라이브러리로 배포하지 않는다.
- `oss-contract`의 계층 규칙을 따른다.
- platform 내부에서 1계층 상세 구현을 다시 정의하지 않는다.
- 3계층 application은 policy와 configuration만 공급한다.
- 2계층 공개 표면은 `properties`, `customizer`, `override bean`으로만 확장한다.
- boundary/clientType/authMode 선택은 profile-aware resolver/provider override로 확장한다.
- 2계층은 서비스별 비즈니스 로직, 도메인 권한 판단, 회원가입, 토큰 발급 비즈니스, 특정 서비스 URL, Redis key 규칙을 포함하지 않는다.
- 2계층 버전은 내부 서비스 간 호환성을 우선한다.
- 운영에서 `SecurityContextResolver`가 없으면 fail-fast 한다.
- dev fallback resolver는 `platform.security.auth.dev-fallback.enabled=true`일 때만 등록한다.
- `platform-security-core`는 순수 Java policy / engine 책임만 가진다.
- `platform-security-policy`는 공통 경계, 인증 모드, 클라이언트 타입, 공통 설정 모델을 가진다.
- `platform-security-auth`는 auth OSS 8개 모듈을 서비스용 인증 capability로 조립한다.
- `platform-security-ip`는 ip-guard OSS를 서비스 경계 IP 보호 capability로 조립한다.
- `platform-security-rate-limit`는 rate-limiter OSS를 서비스 요청 제한 capability로 조립한다.
- `platform-security-web`는 HTTP / Servlet / WebFlux 경계 적응만 가진다.
- `platform-security-autoconfigure`는 Spring bean 조립을 제공한다.
- `platform-security-starter`는 얇은 dependency aggregator다.

## 외부 OSS

- `ip-guard`: `io.github.jho951:ip-guard-core:3.0.0`, `io.github.jho951:ip-guard-spi:3.0.0`
- `rate-limiter`: `io.github.jho951:rate-limiter-core:2.0.0`, `io.github.jho951:rate-limiter-spi:2.0.0`
- `auth`: `io.github.jho951:auth-core:3.0.1`, `io.github.jho951:auth-jwt:3.0.1`, `io.github.jho951:auth-session:3.0.1`, `io.github.jho951:auth-hybrid:3.0.1`, `io.github.jho951:auth-apikey:3.0.1`, `io.github.jho951:auth-hmac:3.0.1`, `io.github.jho951:auth-oidc:3.0.1`, `io.github.jho951:auth-service-account:3.0.1`

## 비공개 배포

이 레포는 GitHub Packages로 비공개 배포한다.

- 릴리스는 `v1.2.3` 같은 tag push에서 publish한다.
- private consumer는 `io.github.jho951.platform` group을 사용한다.
- 실제 publish job은 `.github/workflows/publish.yml`에 있다.
- 현재 확인된 private publish tag는 `v1.0.2`이다.

## 빌드

```bash
./gradlew test
```

## 문서

1. [docs/README.md](docs/README.md)
2. [docs/architecture.md](docs/architecture.md)
3. [docs/modules.md](docs/modules.md)
4. [docs/security-model.md](docs/security-model.md)
5. [docs/configuration.md](docs/configuration.md)
6. [docs/extension-guide.md](docs/extension-guide.md)
7. [docs/troubleshooting.md](docs/troubleshooting.md)
8. [docs/quickstart.md](docs/quickstart.md)
9. [docs/auth-server-integration.md](docs/auth-server-integration.md)
10. [docs/private-publish.md](docs/private-publish.md)
