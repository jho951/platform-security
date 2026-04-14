# Troubleshooting

## 애플리케이션이 `No SecurityContextResolver configured`로 시작 실패

원인:

- `auth.enabled=true`
- `SecurityContextResolver` bean 없음
- dev fallback도 꺼져 있음

해결:

- 운영이면 `SecurityContextResolver` bean을 등록한다.
- local/test이면 `platform.security.auth.dev-fallback.enabled=true`를 명시적으로 켠다.

```java
@Bean
SecurityContextResolver securityContextResolver(
        TokenService tokenService,
        SessionStore sessionStore,
        SessionPrincipalMapper mapper
) {
    return PlatformSecurityContextResolvers.hybrid(tokenService, sessionStore, mapper);
}
```

## 운영정책 위반으로 시작 실패

메시지에 `operational policy violation`이 있으면 운영 profile에서 fail-fast 된 것이다.

확인할 설정:

- `auth.enabled=true`
- `auth.default-mode`가 `NONE`이 아님
- `auth.dev-fallback.enabled=false`
- `SecurityContextResolver` bean 존재
- `ip-guard.enabled=true`
- `ip-guard.admin-allow-cidrs` 값 존재
- `ip-guard.internal-allow-cidrs` 값 존재
- `rate-limit.enabled=true`
- quota 값이 0보다 큼

운영 profile이 아닌데 검사가 돈다면 `platform.security.operational-policy.production` 값을 확인한다.

## 인증 결과가 예상과 다름

확인 순서:

1. 선택한 starter 또는 `service-role-preset`
2. `boundary.*` 매칭 결과
3. `auth.default-mode`
4. credential header/cookie 입력
5. `SecurityContextResolver` 결과
6. `AuthenticationModeResolver` override 여부

브라우저 요청인데 JWT로 해석되거나 API 요청인데 session으로 해석되면 `ClientTypeResolver`와 `auth.allow-*` 설정을 먼저 본다.

## IP 차단이 예상과 다름

확인할 설정:

- `ip-guard.enabled`
- `ip-guard.trust-proxy`
- `ip-guard.admin-allow-cidrs`
- `ip-guard.internal-allow-cidrs`
- 실제 요청의 boundary
- proxy 환경에서 해석된 client IP

`PROTECTED` boundary는 기본적으로 admin/internal CIDR 정책을 받지 않는다.

## Rate limit이 예상과 다름

확인할 설정:

- `rate-limit.enabled`
- `rate-limit.anonymous`
- `rate-limit.authenticated`
- `rate-limit.internal`
- `rate-limit.routes[]`
- `RateLimitKeyResolver` override 여부

`PUBLIC` boundary는 기본 boundary quota를 건너뛴다. 로그인/refresh처럼 public이지만 제한이 필요한 endpoint는 `rate-limit.routes[]`에 등록한다.

## Downstream 신원이 전달되지 않음

확인 순서:

1. 요청 verdict가 allow인지 확인한다.
2. ingress에서 `X-Security-*` header가 scrub 되는지 확인한다.
3. `SecurityDownstreamIdentityPropagator` bean override 여부를 확인한다.
4. downstream 서비스가 기대하는 header 이름과 platform header contract를 맞춘다.

## Spring bean이 안 잡힘

확인할 것:

- starter가 classpath에 있는지 확인한다.
- `platform.security.enabled=false`가 아닌지 확인한다.
- 역할별 starter를 둘 이상 넣지 않았는지 확인한다. internal endpoint가 일부 있는 서비스도 primary role starter 하나만 사용한다.
- 직접 등록한 bean이 `@ConditionalOnMissingBean` 기본 bean을 대체하는지 확인한다.

## GitHub Packages 의존성을 못 받음

확인할 것:

- `https://maven.pkg.github.com/jho951/platform-security` repository 등록
- `GITHUB_ACTOR` 설정
- `GITHUB_TOKEN` 또는 `githubPackagesToken` 설정
- token에 `read:packages` 권한 존재
- private repo/package 접근 권한 존재
- 요청한 version이 실제 publish됨

현재 문서 기준 version은 `1.0.4`다.
