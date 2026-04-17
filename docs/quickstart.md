# Quickstart

## 1. Repository

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

## 2. Dependency

### Edge / Gateway

```gradle
dependencies {
    implementation platform("io.github.jho951.platform:platform-security-bom:1.0.6")
    implementation "io.github.jho951.platform:platform-security-edge-starter"
}
```

### Issuer

```gradle
dependencies {
    implementation platform("io.github.jho951.platform:platform-security-bom:1.0.6")
    implementation "io.github.jho951.platform:platform-security-issuer-starter"
}
```

### Resource Server

```gradle
dependencies {
    implementation platform("io.github.jho951.platform:platform-security-bom:1.0.6")
    implementation "io.github.jho951.platform:platform-security-resource-server-starter"
}
```

### Internal Service

```gradle
dependencies {
    implementation platform("io.github.jho951.platform:platform-security-bom:1.0.6")
    implementation "io.github.jho951.platform:platform-security-internal-service-starter"
}
```

### General Starter

```gradle
dependencies {
    implementation platform("io.github.jho951.platform:platform-security-bom:1.0.6")
    implementation "io.github.jho951.platform:platform-security-starter"
}
```

```yaml
platform:
  security:
    service-role-preset: resource-server
```

## 3. application.yml

```yaml
spring:
  profiles:
    active: prod

platform:
  security:
    enabled: true

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
      enabled: true
      default-mode: HYBRID
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
      routes:
        - name: login
          patterns:
            - /auth/login
            - /v1/auth/login
          requests: 5
          window-seconds: 60
```

## 4. SecurityContextResolver

```java
package com.example.security;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityContextResolver;
import java.util.Set;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

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

```java
package com.example.security;

import io.github.jho951.platform.security.api.SecurityRequest;

interface CurrentUserResolver {
    CurrentUser resolve(SecurityRequest request);
}
```

```java
package com.example.security;

import java.util.Set;

record CurrentUser(String id, Set<String> roles) {
}
```

## 5. RateLimiter

```java
package com.example.security;

import io.github.jho951.ratelimiter.spi.RateLimiter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class RateLimitConfig {

    @Bean
    RateLimiter rateLimiter(RedisClient redisClient) {
        return new RedisBackedRateLimiter(redisClient);
    }
}
```

## 6. Internal Token

```java
package com.example.security;

import io.github.jho951.platform.security.auth.InternalTokenClaimsValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class InternalSecurityConfig {

    @Bean
    InternalTokenClaimsValidator internalTokenClaimsValidator() {
        return (principal, request) ->
                "internal-api".equals(principal.getAttribute("aud"));
    }
}
```

## 7. Audit

```java
package com.example.security;

import io.github.jho951.platform.security.api.SecurityAuditPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class SecurityAuditConfig {

    @Bean
    SecurityAuditPublisher securityAuditPublisher() {
        return event -> {
            // save event
        };
    }
}
```

```gradle
dependencies {
    implementation "io.github.jho951.platform:platform-security-governance-bridge"
}
```

## 8. Outbound Client

```gradle
dependencies {
    implementation "io.github.jho951.platform:platform-security-client"
}
```

## 9. Failure Response

```java
package com.example.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.jho951.platform.security.web.SecurityFailureResponseWriter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class SecurityFailureResponseConfig {

    @Bean
    SecurityFailureResponseWriter securityFailureResponseWriter(ObjectMapper objectMapper) {
        return (request, response, failure) -> {
            GlobalResponse<Object> body = GlobalResponse.fail(
                    failure.status(),
                    failure.message(),
                    failure.code()
            );

            response.setStatus(failure.status());
            response.setContentType("application/json");
            objectMapper.writeValue(response.getWriter(), body);
        };
    }
}
```

```java
package com.example.security;

record GlobalResponse<T>(int httpStatus, boolean success, String message, String code, T data) {
    static <T> GlobalResponse<T> fail(int httpStatus, String message, String code) {
        return new GlobalResponse<>(httpStatus, false, message, code, null);
    }
}
```

## 10. Local/Test

```gradle
dependencies {
    testImplementation "io.github.jho951.platform:platform-security-local-support"
}
```

```yaml
platform:
  security:
    local-support:
      enabled: true
    auth:
      dev-fallback:
        enabled: true
```

## 11. Test

```bash
./gradlew test
```
