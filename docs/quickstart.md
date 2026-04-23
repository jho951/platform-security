# Quickstart

Spring Boot 서비스는 BOM과 단일 starter를 붙인다.

서비스별 차이는 artifact가 아니라 `platform.security.service-role-preset`과 세부 설정으로 표현한다.

## Repository

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

```bash
export GITHUB_ACTOR=jho951
export GITHUB_TOKEN=<read:packages 권한이 있는 PAT>
```

## Dependency

```gradle
dependencies {
    implementation platform("io.github.jho951.platform:platform-security-bom:3.0.0")
    implementation "io.github.jho951.platform:platform-security-starter"
}
```

raw auth/rate-limit bean을 그대로 연결해야 하는 서비스만 optional bridge starter를 추가한다.

```gradle
dependencies {
    implementation "io.github.jho951.platform:platform-security-auth-bridge-starter"
    implementation "io.github.jho951.platform:platform-security-ratelimit-bridge-starter"
}
```

## Minimal Config

```yaml
spring:
  profiles:
    active: prod

platform:
  security:
    service-role-preset: api-server

    boundary:
      public-paths:
        - /health
        - /actuator/health
      protected-paths:
        - /api/**
      admin-paths:
        - /admin/**
      internal-paths:
        - /internal/**

    auth:
      dev-fallback:
        enabled: false

    ip-guard:
      trust-proxy: true
      trusted-proxy-cidrs:
        - 10.0.0.0/8
      admin:
        rules:
          - 10.0.0.0/8
      internal:
        rules:
          - 172.16.0.0/12
```

사용 가능한 preset은 `edge`, `issuer`, `api-server`, `internal-service`다.

## Required Beans

운영 서비스는 현재 사용자를 찾는 `SecurityContextResolver`를 제공해야 한다.

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

운영에서 rate limit을 켜면 공유 저장소 기반 구현을 `PlatformRateLimitPort`로 연결한다. raw `RateLimiter`는 adapter 내부 helper로만 쓰고, service-facing 계약과 policy/public surface는 platform port만 본다.

```java
@Bean
PlatformRateLimitPort platformRateLimitPort(RedisClient redisClient) {
    return new DefaultPlatformRateLimitAdapter(new RedisBackedRateLimiter(redisClient));
}
```

strict 기준에서 서비스는 `PlatformTokenIssuerPort`, `PlatformSessionIssuerPort`, `PlatformSessionSupportFactory`, `PlatformRateLimitPort` 같은 platform port를 제공하거나 adapter 모듈을 선택하는 쪽이 우선이다. raw `TokenService`, `SessionStore`, `RateLimiter`는 adapter layer 내부에서만 소비하는 것이 목표 경계다. `internal-service` 또는 internal token을 쓰는 서비스는 runtime validation hook인 `InternalTokenClaimsValidator`를 제공한다.

## Optional Addons

`platform-security-governance-bridge`는 `platform-security` release에 포함되지 않는다.
governance audit 연동이 필요한 서비스만 `platform-integrations` repository를 추가하고 bridge artifact를 붙인다.
`platform-security` 자체에는 `platform-integrations` 의존성을 추가하지 않는다.

gateway가 hybrid mode에서 ingress를 직접 조립해야 하면 `platform-security-hybrid-web-adapter`를 추가한다. Servlet gateway는 `PlatformSecurityGatewayIntegration`, WebFlux gateway는 `PlatformSecurityReactiveGatewayIntegration` bean을 사용한다.

```gradle
repositories {
    maven {
        url = uri("https://maven.pkg.github.com/jho951/platform-integrations")
        credentials {
            username = findProperty("githubPackagesUsername") ?: System.getenv("GITHUB_ACTOR")
            password = findProperty("githubPackagesToken") ?: System.getenv("GITHUB_TOKEN")
        }
    }
}
```

```gradle
dependencies {
    implementation "io.github.jho951.platform:platform-security-client"
    implementation "io.github.jho951.platform:platform-security-hybrid-web-adapter"
    implementation "io.github.jho951.platform:platform-security-legacy-compat"
    implementation "io.github.jho951.platform:platform-security-governance-bridge:3.0.0"
    implementation "io.github.jho951.platform:platform-security-policyconfig-bridge"
    testImplementation "io.github.jho951.platform:platform-security-support-local"
    testImplementation "io.github.jho951.platform:platform-security-test-support"
}
```

`platform-security-web` 구현 모듈을 서비스가 직접 붙이지 않는다. web 확장은 `platform-security-web-api`와 `SecurityRequestAttributeContributor` 같은 public contract로 닫는다.
`local-support`는 local/test에서만 쓴다.

```yaml
platform:
  security:
    local-support:
      enabled: true
    auth:
      dev-fallback:
        enabled: true
```

## Verify

```bash
./gradlew test
```
