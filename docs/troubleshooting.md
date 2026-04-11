# Troubleshooting

## 1. 인증이 예상과 다르다

- `auth.enabled`와 `auth.default-mode`를 확인한다.
- `SecurityContext.authenticated()`가 실제 요청과 일치하는지 확인한다.
- `platform-security-autoconfigure`에서 auth policy bean이 덮어써졌는지 확인한다.

## 2. IP 차단이 의도와 다르다

- `ip-guard.enabled`가 켜져 있는지 확인한다.
- `ip-guard.trust-proxy`와 `ip-guard.admin-allow-cidrs` / `ip-guard.internal-allow-cidrs` 값을 확인한다.
- trusted proxy 뒤에 있다면 `client IP 해석` 단계가 먼저 적용되는지 확인한다.

## 3. rate limit이 너무 빨리 막힌다

- `rate-limit.anonymous`, `rate-limit.authenticated`, `rate-limit.internal`의 `requests`와 `window-seconds`를 확인한다.
- subject가 없으면 IP 기준으로 제한될 수 있다.
- 여러 인스턴스에서 같은 키를 쓰면 정책 체감이 더 빠를 수 있다.

## 4. downstream 신원이 전달되지 않는다

- 요청이 allow 되었는지 먼저 확인한다.
- `platform-security-web`에서 header scrub이 먼저 적용되는지 확인한다.
- 서비스가 기대하는 downstream header 이름을 platform 설정과 맞춘다.

## 5. Spring bean이 안 잡힌다

- `platform.security.enabled`가 `true`인지 확인한다.
- `platform-security-autoconfigure`가 classpath에 있는지 확인한다. `platform-security-starter`는 얇은 의존성 집계 모듈이다.
- 내부 플랫폼 모듈 버전과 1계층 OSS 버전이 서로 맞는지 확인한다.
