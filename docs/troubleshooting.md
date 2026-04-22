# Troubleshooting

문제가 생기면 먼저 아래 순서로 본다.

```text
1. starter를 하나만 넣었는가?
2. boundary path가 맞는가?
3. SecurityContextResolver가 있는가?
4. 운영 Spring profile에서 local/test 기본 구현을 쓰고 있지 않은가?
5. IP rule과 rate-limit adapter가 운영용으로 설정됐는가?
```

## 앱이 시작하지 않음

### `No SecurityContextResolver configured`

뜻:

```text
auth.enabled=true 인데
현재 사용자를 찾는 SecurityContextResolver bean이 없다.
```

해결:

```text
운영 서비스
-> SecurityContextResolver bean을 등록한다.

local/test
-> platform.security.auth.dev-fallback.enabled=true 를 명시적으로 켠다.
```

예:

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

## 운영 안전검사에서 막힘

메시지에 `operational policy violation`이 있으면 운영으로 판단된 상태에서 위험 설정이 발견된 것이다.

운영으로 보는 경우:

```text
Spring profile이 platform.security.operational.production-profiles에 포함됨
또는
platform.security.operational.production=true
```

기본 운영 profile은 `prod`, `production`이다. `live`는 기본값으로는 운영 profile이 아니다.  
기존 `platform.security.operational-policy.*` 설정도 계속 동작한다.

확인할 것:

```text
- auth.enabled=true
- auth.default-mode가 NONE이 아님
- auth.dev-fallback.enabled=false
- SecurityContextResolver bean 존재
- 운영용 token/session/internal token validator 사용
- issuer 서비스라면 운영용 TokenService / SessionStore 존재
- ip-guard.enabled=true
- trust-proxy=true이면 trusted-proxy-cidrs 존재
- admin/internal IP rule 존재
- rate-limit.enabled=true
- 운영용 공유 `PlatformRateLimitAdapter` bean 존재
- quota 값이 0보다 큼
- route limit에는 path가 하나 이상 있음
```

## 인증 결과가 예상과 다름

확인 순서:

```text
1. service-role-preset 설정이 맞는가?
2. path가 의도한 boundary로 잡히는가?
3. Authorization header가 Bearer 형식인가?
4. session cookie나 internal token header가 들어오는가?
5. SecurityContextResolver가 authenticated=true를 반환하는가?
6. auth.default-mode와 auth.allow-* 설정이 맞는가?
```

주의:

```text
Authorization: Bearer xxx
-> access token

Authorization: Basic xxx
-> access token 아님
```

Basic을 써야 하는 서비스는 Basic을 별도로 처리하거나 gateway에서 표준 token으로 바꾼다.

## IP 제한이 예상과 다름

확인할 것:

```text
- 요청 path가 ADMIN 또는 INTERNAL boundary인지
- 요청 주체 ClientType이 ADMIN_CONSOLE 또는 INTERNAL_SERVICE인지
- ip-guard.enabled=true 인지
- trust-proxy 설정이 실제 proxy 구조와 맞는지
- trusted-proxy-cidrs에 proxy IP가 들어 있는지
- admin/internal rules에 client IP가 포함되는지
```

`PROTECTED` path는 일반 `BROWSER`/`EXTERNAL_API` client에게는 admin/internal IP rule을 요구하지 않는다.
다만 요청 주체가 `ADMIN_CONSOLE`이면 admin IP rule을, `INTERNAL_SERVICE`이면 internal IP rule을 강제로 적용한다.
거부 reason에 `policyBasis=CLIENT_TYPE`이 있으면 client type 때문에 적용된 것이고, `policyBasis=PATH`가 있으면 admin/internal path 때문에 적용된 것이다.

예전 설정인 `admin-allow-cidrs`, `internal-allow-cidrs`는 더 이상 지원하지 않는다.
아래처럼 boundary별 `rules`로 옮긴다.

```yaml
platform:
  security:
    ip-guard:
      admin:
        rules:
          - 10.0.0.0/8
      internal:
        rules:
          - 172.16.0.0/12
```

### X-Forwarded-For 판단 방식

`trust-proxy=true`이면 먼저 `remoteAddress`가 `trusted-proxy-cidrs`에 포함되는지 확인한다.
`trusted-proxy-cidrs`가 설정되어 있는데 `remoteAddress`가 포함되지 않으면 `X-Forwarded-For`를 무시하고 `remoteAddress`를 client IP로 쓴다.

`trusted-proxy-cidrs`가 비어 있으면 아무 `remoteAddress`도 신뢰된 proxy로 보지 않는다.
local/dev에서도 proxy header를 쓰려면 `127.0.0.1`, `::1` 같은 loopback proxy 대역을 명시해야 한다.
운영에서는 실제 LB/ingress/proxy IP 대역을 반드시 넣어야 한다.

`remoteAddress`가 신뢰된 proxy이면 `X-Forwarded-For`를 오른쪽에서 왼쪽으로 읽는다.
`trusted-proxy-cidrs`에 포함되는 IP는 proxy chain으로 보고 건너뛰며, 처음 만나는 신뢰되지 않은 IP를 client IP로 쓴다.

예:

```text
remoteAddress: 10.0.0.10
trusted-proxy-cidrs: 10.0.0.0/8, 172.16.0.0/12
X-Forwarded-For: 198.51.100.1, 203.0.113.9, 172.16.2.20, 10.0.0.9

client IP: 203.0.113.9
```

주의:

```text
- trusted-proxy-cidrs에는 proxy/LB/ingress 대역만 넣는다.
- client가 속할 수 있는 사내망/VPN 대역을 proxy 대역으로 넣으면 실제 client IP도 proxy로 오인될 수 있다.
- X-Forwarded-For에 유효하지 않은 IP 값이 있으면 client IP 후보에서 제외한다.
- X-Forwarded-For의 모든 유효 IP가 trusted-proxy-cidrs에 포함되면 remoteAddress를 client IP로 쓴다.
```

### Rule 문법 확인

```text
trusted-proxy-cidrs
-> trusted proxy exact IP 또는 CIDR

admin.rules / internal.rules
-> ip-guard rule 문법
-> CIDR과 range rule 사용 가능
```

예:

```yaml
platform:
  security:
    ip-guard:
      trusted-proxy-cidrs:
        - 10.0.0.0/8
      admin:
        rules:
          - 10.0.0.0/8
          - 203.0.113.10
      internal:
        rules:
          - 172.16.0.0/12
          - 2001:db8::1-2001:db8::f
```

## 요청 횟수 제한이 예상과 다름

확인할 것:

```text
- rate-limit.enabled=true 인지
- anonymous/authenticated/internal quota가 맞는지
- route limit path가 실제 path와 매칭되는지
- RateLimitKeyResolver를 바꿨는지
- 운영에서 공유 `PlatformRateLimitAdapter`를 쓰는지
- 기존 `RateLimiter`를 감싸는 방식이면 backing store가 분산 저장소인지
```

`PUBLIC` path는 기본 quota를 건너뛴다.  
로그인 같은 public endpoint를 제한하려면 `rate-limit.routes[]`에 등록한다.

## 보안 감사 기록이 안 남음

직접 저장하려면:

```text
SecurityAuditPublisher bean이 있는지 확인한다.
```

governance audit에 남기려면:

```text
- platform-integrations repository에서 받은 platform-security-governance-bridge가 classpath에 있는지
- AuditLogRecorder bean이 있는지
- 직접 등록한 SecurityAuditPublisher가 bridge 기본 bean을 대체하지 않았는지
```

## 다음 서비스로 사용자 정보가 안 넘어감

확인할 것:

```text
- 현재 요청이 allow 되었는지
- platform-security-client를 추가했는지
- RestTemplate / RestClient / WebClient / Feign 중 실제 사용하는 client에 interceptor/filter가 붙었는지
- 다음 서비스가 X-Security-* header를 기대하는지
```

외부에서 들어온 `X-Security-*` header는 먼저 제거된다.  
신뢰할 수 없는 사용자가 내부 사용자 정보를 위조하지 못하게 하기 위한 동작이다.

## Spring bean이 안 잡힘

확인할 것:

```text
- starter가 classpath에 있는지
- platform.security.enabled=false 가 아닌지
- 직접 등록한 bean이 기본 bean을 대체하는지
```

## GitHub Packages 의존성을 못 받음

확인할 것:

```text
- https://maven.pkg.github.com/jho951/platform-security repository 등록
- GITHUB_ACTOR 설정
- GITHUB_TOKEN 또는 githubPackagesToken 설정
- token에 read:packages 권한 존재
- private repo/package 접근 권한 존재
- 요청한 version이 실제 publish됨
```

자주 보는 오류:

| 오류 | 보통 원인 |
| --- | --- |
| `401 Unauthorized` | token 없음 또는 `read:packages` 없음 |
| `403 Forbidden` | package/repo 접근 권한 부족 |
| `Could not find artifact` | version 미배포 또는 repository URL 오류 |
