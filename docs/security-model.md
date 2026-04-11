# Security Model

`platform-security`는 요청 단위로 boundary와 profile을 해석하고, 그 결과에 따라 authentication, ip-guard, rate limit을 조립해 평가한다.

## 평가 순서

1. header scrub과 client IP 해석
2. boundary 결정
3. profile 선택
4. profile에 따른 auth 실행
5. profile에 따른 ip-guard 실행
6. profile에 따른 rate limit 실행
7. 모두 통과하면 allow

## 결과

- `ALLOW`
- `DENY`

## 기준

- 정책 실패는 401, 403, 429 중 하나로 표준화한다.
- boundary/profile은 3계층 application이 공급한다.
- 서비스별 URL, Redis key, role 이름은 여기서 정의하지 않는다.
