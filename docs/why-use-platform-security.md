# Why Use Platform Security

3계층 서비스마다 보안을 직접 조립하면 서비스별 차이가 생긴다. `platform-security`는 인증, IP 제한, rate limit, 실패 응답, 운영 안전검사를 같은 흐름으로 묶는다.

## 해결하는 문제

서비스별로 직접 조립하면 아래 차이가 생기기 쉽다.

```text
- 어떤 서비스는 Basic header를 JWT처럼 처리한다.
- 어떤 서비스는 admin/internal IP 제한을 빠뜨린다.
- 어떤 서비스는 dev secret이나 local token store를 운영에 들고 간다.
- 어떤 서비스는 rate limit 기준을 IP로 잡고, 다른 서비스는 user id로 잡는다.
- 어떤 서비스는 보안 감사 기록을 남기고, 다른 서비스는 남기지 않는다.
```

보안 흐름의 차이는 운영 장애나 취약점으로 이어질 수 있다.

## 사용하는 방식

3계층 서비스는 같은 dependency를 쓴다.

```gradle
dependencies {
    implementation platform("io.github.jho951.platform:platform-security-bom:4.0.0")
    implementation "io.github.jho951.platform:platform-security-starter"
}
```

서비스 역할은 설정으로 고른다.

```yaml
platform:
  security:
    service-role-preset: api-server
```

사용 가능한 preset은 `edge`, `issuer`, `api-server`, `internal-service`다.

## 표준화하는 것

```text
HTTP 요청
-> path boundary 분류
-> 현재 사용자 확인
-> 인증 확인
-> admin/internal IP 제한
-> 요청 횟수 제한
-> 실패 응답 표준화
-> 보안 판단 기록
-> controller
```

인증값도 의미대로 분류한다.

```text
Authorization: Bearer xxx
-> access token

Authorization: Basic xxx
-> access token 아님

X-Auth-Internal-Token: xxx
-> internal token
```

## 운영 안전검사

운영에서는 위험한 설정을 부팅 시점에 막는다.

```text
- SecurityContextResolver 없음
- dev fallback 사용
- dev JWT secret 사용
- local token/session adapter 사용
- local InternalTokenClaimsValidator 사용
- local/in-memory PlatformRateLimitPort 사용
- admin/internal IP rule 없음
```

운영 요청을 받은 뒤에 실패하는 것보다 시작 단계에서 막는 편이 안전하다.

## 3계층 책임

`platform-security`는 서비스 업무 의미를 모른다. 아래 판단은 3계층에 둔다.

```text
- 로그인 성공 여부
- password / MFA 검증
- 사용자 상태 판단
- 문서 소유자 판단
- 조직 관리자 판단
- 결제 가능 여부 판단
- 업무 use case 실행
```

대표 연결점은 `SecurityContextResolver`다. 이 bean은 “우리 서비스에서는 현재 사용자를 이렇게 찾는다”를 2계층에 알려준다.

## 넣지 않는 것

2계층에는 서비스 이름별 분기나 업무 규칙을 넣지 않는다.

```text
- 특정 gateway 전용 if문
- 특정 auth 서비스의 password 검증
- 특정 user 서비스의 본인 프로필 수정 규칙
- 특정 resource 서비스의 문서 소유자 판단
- 특정 payment 서비스의 결제 가능 여부
```

기준은 단순하다.

```text
여러 서비스가 같은 방식으로 써야 하는 보안 흐름
-> platform-security

서비스 데이터나 업무 의미가 필요한 판단
-> 3계층
```
