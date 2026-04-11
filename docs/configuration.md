# Configuration

`platform-security`는 `platform.security.*` prefix로 설정한다.

## 기본 속성

- `enabled`
- `authentication.required`
- `ip-guard.enabled`
- `ip-guard.allowed-ips`
- `rate-limit.enabled`
- `rate-limit.limit`
- `rate-limit.window`

## 설계 관점

- `authentication.required`는 auth step 여부를 나타낸다.
- `ip-guard.*`는 boundary/profile에 따라 전달되는 IP 정책 입력이다.
- `rate-limit.*`는 profile이 선택한 quota 입력이다.
- 서비스별 boundary pattern, trusted proxy, downstream 전달 규칙은 application이 공급한다.

## 기본 동작

- authentication은 기본 활성화
- IP guard는 기본 비활성화
- rate limit은 기본 비활성화

## 설정 예시

```yaml
platform:
  security:
    authentication:
      required: true
    ip-guard:
      enabled: true
      allowed-ips:
        - 127.0.0.1
    rate-limit:
      enabled: true
      limit: 100
      window: PT1M
```
