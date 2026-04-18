# Security Model

이 문서는 요청 하나가 들어왔을 때 `platform-security`가 무엇을 확인하는지 설명한다.

## 핵심 용어

| 이름 | 쉬운 뜻 |
| --- | --- |
| `SecurityRequest` | HTTP 요청을 보안 검사용 형태로 바꾼 값 |
| `SecurityContext` | 현재 요청의 사용자가 누구인지 담은 값 |
| `Boundary` | 이 요청이 public/protected/admin/internal 중 어디에 속하는지 |
| `ClientType` | 브라우저 요청인지, API 요청인지, 내부 서비스 요청인지 |
| `AuthMode` | JWT, session, API key 같은 인증 방식 |
| `SecurityEvaluationResult` | 최종 허용/거부 결과 |

## 요청 평가 순서

```text
1. HTTP 요청을 SecurityRequest로 바꾼다.
2. 외부에서 보내면 안 되는 X-Security-* header를 제거한다.
3. client IP를 계산한다.
4. path를 보고 boundary를 정한다.
5. 3계층이 제공한 SecurityContextResolver로 현재 사용자를 찾는다.
6. 인증을 확인한다.
7. client type을 먼저 보고, 필요하면 path boundary를 방어선으로 사용해 IP rule을 확인한다.
8. 요청 횟수 제한을 확인한다.
9. 실패하면 401/403/429 중 하나로 응답한다.
10. 성공하면 controller로 넘긴다.
```

중요한 순서:

```text
boundary 계산
-> 현재 사용자 찾기
-> 인증 / IP 제한 / 요청 횟수 제한
```

internal 요청은 boundary를 먼저 알아야 어떤 내부 인증을 쓸지 고를 수 있다.

## Boundary

boundary는 “이 path를 어떤 문으로 볼 것인가”다.

| Boundary | 뜻 |
| --- | --- |
| `PUBLIC` | 로그인 없이 열어둔 path |
| `PROTECTED` | 로그인한 사용자만 접근하는 path |
| `ADMIN` | 관리자용 path |
| `INTERNAL` | 서비스끼리 호출하는 내부 path |

예:

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
```

## IP Guard Matrix

IP guard는 Profile-First, Path-Guard 원칙으로 선택한다.

```text
1. resolved client type이 우선이다.
2. client type이 높은 권한을 뜻하지 않으면 path boundary를 방어선으로 사용한다.
3. PROTECTED path의 일반 사용자 요청은 IP rule 없이 인증만 확인한다.
```

| ClientType | Target Path | 적용 IP Policy | 비고 |
| --- | --- | --- | --- |
| `ADMIN_CONSOLE` | any | admin IP rule | 관리자 세션은 path와 무관하게 추가로 제한한다. |
| `INTERNAL_SERVICE` | any | internal IP rule | 서비스 간 통신은 path와 무관하게 내부망 제한을 받는다. |
| `BROWSER`, `EXTERNAL_API` | `ADMIN` | admin IP rule | 일반 client가 admin path를 호출하면 path 기준 방어선을 적용한다. |
| `BROWSER`, `EXTERNAL_API` | `INTERNAL` | internal IP rule | 일반 client가 internal path를 호출하면 path 기준 방어선을 적용한다. |
| `BROWSER`, `EXTERNAL_API` | `PROTECTED` | 없음 | 인증만 통과하면 IP 대역은 제한하지 않는다. |
| `BROWSER`, `EXTERNAL_API` | `PUBLIC` | 없음 | 공개 path는 일반 client에게 IP rule을 적용하지 않는다. |

IP guard가 거부하면 verdict reason과 audit event에 `boundary`, `clientType`, `policyBasis`가 같이 남는다.
예를 들어 `boundary=PROTECTED, clientType=ADMIN_CONSOLE, policyBasis=CLIENT_TYPE`이면 path가 아니라 client type 때문에 admin IP rule이 적용된 것이다.

## 인증값 분류

2계층은 인증값을 막는 것이 아니라 정확히 분류한다.

```text
Authorization: Bearer xxx
-> access token으로 사용

Authorization: Basic xxx
-> access token으로 사용하지 않음

Authorization: Digest xxx
-> access token으로 사용하지 않음

X-Auth-Internal-Token: xxx
-> internal token으로 사용

Session cookie
-> session id로 사용
```

Basic이나 Digest를 금지한다는 뜻이 아니다.  
Bearer token이 아닌 값을 Bearer token처럼 착각하지 않겠다는 뜻이다.

Basic 인증을 지원해야 하는 서비스는 gateway/edge나 별도 인증 처리에서 표준 token으로 바꾼 뒤 넘기는 방식이 좋다.

## Client IP

proxy 뒤에 있으면 실제 client IP는 `X-Forwarded-For` 같은 header에 들어올 수 있다.

하지만 아무 요청의 proxy header나 믿으면 안 된다.  
그래서 proxy header를 사용할 서비스는 `trust-proxy=true`와 `trusted-proxy-cidrs`를 명시한다.

```yaml
platform:
  security:
    ip-guard:
      trust-proxy: true
      trusted-proxy-cidrs:
        - 10.0.0.0/8
```

뜻:

```text
10.0.0.0/8 안에 있는 proxy가 보낸 X-Forwarded-For만 믿는다.
```

`trusted-proxy-cidrs`가 비어 있으면 `X-Forwarded-For`를 믿지 않는다.
local/dev에서 proxy header를 쓰려면 `127.0.0.1`, `::1` 같은 loopback proxy도 명시한다.

`trusted-proxy-cidrs`는 exact IP 또는 CIDR만 받는다.
admin/internal 접근 제한 rule은 `admin.rules`, `internal.rules`에 따로 적으며 CIDR과 range rule을 사용할 수 있다.

## 실패 응답

기본 실패 응답은 아래처럼 맞춘다.

| 상황 | 응답 |
| --- | --- |
| 인증 실패 | `401` |
| 권한/IP 제한 실패 | `403` |
| 요청 횟수 초과 | `429` |

이 값은 모든 서비스가 같은 방식으로 실패하도록 하는 기본값이다.  
필요하면 3계층에서 response writer를 교체할 수 있다.

```text
Servlet
-> SecurityFailureResponseWriter

WebFlux
-> ReactiveSecurityFailureResponseWriter
```

## 보안 판단 기록

`platform-security`는 보안 판단 결과를 정리해서 `SecurityAuditEvent`로 만든다.

```text
SecurityEvaluationResult
-> SecurityAuditEvent
-> SecurityAuditPublisher
```

감사 기록을 어디에 저장할지는 3계층이 정한다.  
governance와 연결하고 싶으면 `platform-integrations` repository의 bridge 모듈을 붙인다.

## 내부 호출 사용자 정보

요청이 허용되면 다음 서비스로 넘길 사용자 정보를 만들 수 있다.

```text
SecurityContext
-> X-Security-* header
-> 다음 서비스
```

3계층은 header 이름을 직접 만들지 말고 `platform-security-client`를 사용한다.

신뢰 기준:

```text
외부 요청이 보낸 X-Security-* header
-> 신뢰하지 않음
-> platform-security filter가 제거

platform-security filter가 만든 X-Security-* header
-> 내부 호출에서만 신뢰

서비스가 임의로 만든 X-Security-* header
-> 신뢰하지 않는 것이 원칙
```
