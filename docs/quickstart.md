# Quickstart

이 문서는 3계층 Spring Boot 서비스에 `platform-security`를 붙이는 최소 절차다.

## 1. Repository 설정

`platform-security`는 private GitHub Packages로 배포된다.

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

로컬 환경 변수:

```bash
export GITHUB_ACTOR=jho951
export GITHUB_TOKEN=<read:packages 권한이 있는 PAT>
```

## 2. Starter 선택

서비스는 BOM과 starter 하나만 사용한다.

```gradle
dependencies {
    implementation platform("io.github.jho951.platform:platform-security-bom:1.0.5")
    implementation "io.github.jho951.platform:platform-security-resource-server-starter"
}
```

governance audit까지 같은 체계로 남기는 서비스는 bridge를 추가한다.

```gradle
dependencies {
    implementation "io.github.jho951.platform:platform-security-governance-bridge"
}
```

역할별 starter는 서비스의 주 역할(primary role)을 기준으로 하나만 고른다.

| 서비스 역할 | Starter |
| --- | --- |
| gateway/edge | `platform-security-edge-starter` |
| login/token/session issuer | `platform-security-issuer-starter` |
| 일반 API 서버 | `platform-security-resource-server-starter` |
| 전체가 내부 호출 전용인 서비스 | `platform-security-internal-service-starter` |

한 서비스에 여러 종류의 endpoint가 있어도 starter를 여러 개 넣지 않는다. 예를 들어 auth-server에 internal API가 있어도 `platform-security-issuer-starter` 하나만 사용하고 internal endpoint는 `boundary.internal-paths`로 선언한다.

역할 preset을 직접 설정하려면 일반 starter를 사용한다.

```gradle
implementation "io.github.jho951.platform:platform-security-starter"
```

```yaml
platform:
  security:
    service-role-preset: resource-server
```

## 3. 최소 설정

```yaml
platform:
  security:
    boundary:
      public-paths:
        - /health
      protected-paths:
        - /api/**
      admin-paths:
        - /admin/**
      internal-paths:
        - /internal/**

    auth:
      enabled: true
      dev-fallback:
        enabled: false

    ip-guard:
      enabled: true
      trust-proxy: true
      trusted-proxy-cidrs:
        - 10.0.0.0/8
      admin:
        source: INLINE
        rules:
          - 10.0.0.0/8
      internal:
        source: INLINE
        rules:
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
```

로그인, refresh, OAuth2 시작점처럼 public이지만 공격 대상인 endpoint는 route limit을 추가한다.

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

운영에서 `trust-proxy=true`이면 `trusted-proxy-cidrs`가 필요하다. 이 값에 포함된 proxy에서 온 요청의 `X-Forwarded-For`만 client IP로 신뢰한다.

## 4. 운영용 resolver 등록

`auth.enabled=true`이면 운영 서비스는 `SecurityContextResolver`를 직접 제공해야 한다.
기본 경로에서는 auth 1계층 `TokenService`, `SessionStore`, provider 타입을 직접 조립하지 않는다.

```java
@Configuration
class PlatformSecurityConfig {

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
}
```

local/test에서만 dev fallback을 쓴다.

```yaml
platform:
  security:
    auth:
      dev-fallback:
        enabled: true
```

## 5. 자주 쓰는 override

Internal token claim 검증:

```java
@Bean
InternalTokenClaimsValidator internalTokenClaimsValidator() {
    return (principal, request) -> "internal-api".equals(principal.getAttribute("aud"));
}
```

Rate limit key 변경:

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

운영용 공유 rate limiter:

```java
@Bean
RateLimiter rateLimiter(RedisClient redisClient) {
    return new RedisBackedRateLimiter(redisClient);
}
```

`platform-security`가 제공하는 기본 token service, session store, internal token validator, in-memory rate limiter는 local/test용이다. 운영 profile에서는 서비스가 운영용 bean을 제공하지 않으면 fail-fast 된다.

Audit event 발행:

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

`platform-security-governance-bridge`를 사용하면 `AuditLogRecorder` bean이 있을 때 `SecurityAuditPublisher`가 자동 등록된다. 직접 `SecurityAuditPublisher` bean을 등록하면 bridge 기본 bean을 대체한다.

## 6. 확인

```bash
./gradlew test
```

GitHub Packages 인증 문제가 나면 먼저 확인한다.

```bash
echo "$GITHUB_ACTOR"
test -n "$GITHUB_TOKEN" && echo "token exists"
```
