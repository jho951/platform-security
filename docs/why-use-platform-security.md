# Why Use Platform Security

이 문서는 3계층 서비스가 1계층 OSS를 바로 조립하지 않고, 왜 `platform-security`를 거쳐야 하는지 설명한다.

## 한 줄 결론

```text
3계층 서비스마다 보안을 직접 조립하면 서비스별 차이가 생긴다.
platform-security를 거치면 공통 보안 흐름을 한 번 정하고 여러 서비스가 같이 쓴다.
```

## 계층을 쉽게 보면

```text
1계층 = JWT 검증, IP rule 평가, 요청 횟수 계산 같은 기본 기능을 제공하는 OSS
2계층 = 1계층 OSS를 소비해서 서비스들이 같은 방식으로 쓰게 만든 platform-security
3계층 = 실제 배포되는 서비스
```

## 1계층을 바로 조립하면 생기는 문제

서비스마다 auth, IP 제한, rate limit OSS를 직접 조립하면 처음에는 자유로워 보인다.  
하지만 시간이 지나면 보안 동작이 조금씩 달라진다.

예:

```text
- 어떤 서비스는 Basic header를 JWT처럼 넘긴다.
- 어떤 서비스는 admin IP 제한을 빼먹는다.
- 어떤 서비스는 dev secret을 운영에 들고 간다.
- 어떤 서비스는 rate limit 기준을 IP로 잡고, 다른 서비스는 user id로 잡는다.
- 어떤 서비스는 audit을 남기고, 다른 서비스는 남기지 않는다.
- 어떤 서비스는 session과 JWT 처리 순서가 다르다.
```

보안에서 이런 차이는 운영 장애나 취약점으로 이어질 수 있다.

## 2계층을 쓰면 좋아지는 점

### 1. 붙이는 방법이 같아진다

3계층 서비스는 BOM과 starter 하나를 붙인다.

```gradle
dependencies {
    implementation platform("io.github.jho951.platform:platform-security-bom:1.0.6")
    implementation "io.github.jho951.platform:platform-security-resource-server-starter"
}
```

서비스 역할이 다르면 starter만 바꾼다.

```text
gateway/edge
-> platform-security-edge-starter

token/session 발급 서비스
-> platform-security-issuer-starter

일반 API 서비스
-> platform-security-resource-server-starter

내부 전용 서비스
-> platform-security-internal-service-starter
```

### 2. 요청 처리 순서가 같아진다

모든 서비스가 같은 순서로 보안을 확인한다.

```text
HTTP 요청
-> path 분류
-> 현재 사용자 찾기
-> 인증 확인
-> IP 제한 확인
-> 요청 횟수 제한 확인
-> 실패 응답 표준화
-> 보안 판단 기록
-> controller
```

각 서비스가 filter 순서를 직접 맞추지 않아도 된다.

### 3. 인증값을 정확히 분류한다

```text
Authorization: Bearer xxx
-> access token

Authorization: Basic xxx
-> access token 아님

X-Auth-Internal-Token: xxx
-> internal token

Session cookie
-> session id
```

이건 Basic을 금지한다는 뜻이 아니다.  
Basic 값을 Bearer token처럼 착각하지 않게 만드는 것이다.

### 4. 실패 응답이 같아진다

```text
인증 실패
-> 401

권한/IP 제한 실패
-> 403

요청 횟수 초과
-> 429
```

서비스마다 다른 응답 형식이 필요하면 3계층에서 실패 응답 writer를 교체할 수 있다.

### 5. 운영 실수를 시작 전에 막는다

운영에서는 위험한 설정을 부팅 시점에 막는다.

```text
- 테스트용 기본 인증 사용
- dev JWT secret 사용
- local token/session 구현 사용
- 메모리 기반 rate limiter 사용
- RateLimiter 누락
- SecurityContextResolver 누락
- admin/internal IP rule 누락
```

운영 요청을 받은 뒤에 터지는 것보다, 애플리케이션 시작 단계에서 막는 편이 안전하다.

### 6. 1계층 변경을 2계층에서 흡수한다

1계층 OSS를 서비스마다 직접 조립하면 auth/ip/rate-limit 조립 방식이 바뀔 때 모든 서비스가 영향을 받는다.

```text
gateway 수정
auth 수정
user 수정
block 수정
새로 추가된 서비스도 각각 수정
```

2계층을 거치면 변경 지점이 줄어든다.

```text
platform-security 수정
platform-security 새 버전 배포
3계층은 BOM/starter 버전 업데이트
```

## 3계층이 여전히 해야 하는 일

`platform-security`를 쓴다고 3계층 책임이 없어지는 것은 아니다.

3계층은 서비스 의미를 안다. 그래서 아래는 3계층에 둔다.

```text
- 로그인 성공 여부
- password / MFA 검증
- 사용자 상태 판단
- 문서 소유자 판단
- 조직 관리자 판단
- 결제 가능 여부 판단
- 업무 use case 실행
```

대표 연결점은 `SecurityContextResolver`다.

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

이 코드는 “우리 서비스에서는 현재 사용자를 이렇게 찾는다”를 2계층에 알려준다.

## 2계층에 넣으면 안 되는 것

`platform-security`는 서비스 이름과 업무 규칙을 몰라야 한다.

넣으면 안 되는 것:

```text
- 특정 gateway 전용 if문
- 특정 auth 서비스의 password 검증
- 특정 user 서비스의 본인 프로필 수정 규칙
- 특정 resource 서비스의 문서 소유자 판단
- 특정 payment 서비스의 결제 가능 여부
- 특정 서비스 URL 하드코딩
```

이런 로직은 3계층에 둔다.

## 판단 기준

어디에 둘지 헷갈리면 이렇게 나눈다.

```text
JWT 검증, IP rule 평가, counter 증가처럼 작은 기본 기능인가?
-> 1계층

여러 서비스가 같은 방식으로 써야 하는 보안 흐름인가?
-> 2계층

서비스 데이터나 업무 의미를 알아야 판단 가능한가?
-> 3계층
```

예:

```text
JWT signature 검증
-> 1계층

Bearer token만 access token으로 분류
-> 2계층

운영에서 in-memory rate limiter 차단
-> 2계층

로그인 password와 MFA 검증
-> 3계층

문서 작성자만 수정 가능
-> 3계층
```
