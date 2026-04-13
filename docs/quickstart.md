# Quickstart

이 문서는 3계층 Spring Boot 서비스가 `platform-security`를 붙이는 최소 절차다.

## 1. GitHub Packages 인증 준비

`platform-security`는 private GitHub Packages로 배포된다.
소비 서비스는 package를 내려받기 위해 GitHub Packages credential이 필요하다.

로컬:

```bash
export GITHUB_ACTOR=jho951
export GITHUB_TOKEN=<read:packages 권한이 있는 PAT>
```

CI:

```yaml
env:
  GITHUB_ACTOR: jho951
  GITHUB_TOKEN: ${{ secrets.GH_PACKAGES_TOKEN }}
```

권장 PAT 권한:

- `read:packages`
- private repo/package 접근이 필요하면 `repo`

publish까지 하는 token이면 추가로:

- `write:packages`

## 2. Repository 설정

서비스의 `settings.gradle` 또는 root `build.gradle`에 GitHub Packages repository를 추가한다.

```gradle
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
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
}
```

## 3. Dependency 추가

서비스는 보통 BOM과 starter만 의존한다.

```gradle
dependencies {
    implementation platform("io.github.jho951.platform:platform-security-bom:1.0.3")
    implementation "io.github.jho951.platform:platform-security-starter"
}
```

테스트 fixture가 필요하면 추가한다.

```gradle
testImplementation "io.github.jho951.platform:platform-security-test-support"
```

## 4. 최소 설정

```yaml
platform:
  security:
    enabled: true

    boundary:
      public-paths:
        - /health
        - /auth/login
        - /auth/refresh
      protected-paths:
        - /api/**
      admin-paths:
        - /admin/**
      internal-paths:
        - /internal/**

    auth:
      enabled: true
      default-mode: HYBRID
      allow-session-for-browser: true
      allow-bearer-for-api: true
      internal-token-enabled: true
      dev-fallback:
        enabled: false

    ip-guard:
      enabled: true
      trust-proxy: true
      admin-allow-cidrs:
        - 10.0.0.0/8
      internal-allow-cidrs:
        - 172.16.0.0/12

    rate-limit:
      enabled: true
      anonymous:
        requests: 60
        window-seconds: 60
      authenticated:
        requests: 300
        window-seconds: 60
      internal:
        requests: 1000
        window-seconds: 60
      routes:
        - name: login
          patterns:
            - /auth/login
            - /auth/refresh
          requests: 5
          window-seconds: 60
```

## 5. 운영용 SecurityContextResolver 등록

`auth.enabled=true`이면 운영 서비스는 반드시 `SecurityContextResolver`를 제공해야 한다.
제공하지 않으면 application startup 시 fail-fast 한다.

```java
@Configuration
class PlatformSecurityConfig {

    @Bean
    SecurityContextResolver securityContextResolver(
            TokenService tokenService,
            SessionStore sessionStore,
            SessionPrincipalMapper sessionPrincipalMapper
    ) {
        return PlatformSecurityContextResolvers.hybrid(
                tokenService,
                sessionStore,
                sessionPrincipalMapper
        );
    }
}
```

local/test에서만 dev fallback을 쓸 수 있다.

```yaml
platform:
  security:
    auth:
      dev-fallback:
        enabled: true
```

운영에서 이 값을 켜지 않는다.

## 6. Override 예시

### Internal token claims 검증

```java
@Bean
InternalTokenClaimsValidator internalTokenClaimsValidator() {
    return (principal, request) -> "internal-api".equals(principal.getAttribute("aud"));
}
```

### Rate limit key 변경

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

### Audit event 발행

```java
@Bean
SecurityAuditPublisher securityAuditPublisher() {
    return result -> log.info(
            "security decision={} policy={} principal={}",
            result.verdict().decision(),
            result.verdict().policy(),
            result.evaluationContext().securityContext().principal()
    );
}
```

## 7. 확인 방법

```bash
./gradlew test
```

서비스에서 package 인증 문제가 나면 먼저 아래를 확인한다.

```bash
echo "$GITHUB_ACTOR"
test -n "$GITHUB_TOKEN" && echo "token exists"
```

401/403이면 token 권한 또는 package 접근 권한 문제다.
