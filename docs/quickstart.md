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
    implementation platform("io.github.jho951.platform:platform-security-bom:2.0.0")
    implementation "io.github.jho951.platform:platform-security-starter"
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

운영에서 rate limit을 켜면 공유 저장소 기반 `RateLimiter`를 제공한다.

```java
@Bean
RateLimiter rateLimiter(RedisClient redisClient) {
    return new RedisBackedRateLimiter(redisClient);
}
```

`issuer` preset은 운영용 `TokenService`와 필요한 경우 `SessionStore`를 제공해야 한다. `internal-service` 또는 internal token을 쓰는 서비스는 `InternalTokenClaimsValidator`를 제공한다.

## Optional Addons

`platform-security-governance-bridge`는 `platform-security` release에 포함되지 않는다.
governance audit 연동이 필요한 서비스만 `platform-integrations` repository를 추가하고 bridge artifact를 붙인다.
`platform-security` 자체에는 `platform-integrations` 의존성을 추가하지 않는다.

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
    implementation "io.github.jho951.platform:platform-security-governance-bridge:1.0.0"
    implementation "io.github.jho951.platform:platform-security-policyconfig-bridge"
    testImplementation "io.github.jho951.platform:platform-security-local-support"
    testImplementation "io.github.jho951.platform:platform-security-test-support"
}
```

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
