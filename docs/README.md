# Docs

## 현재 기준

- 1계층 OSS는 공개 배포본이다.
- 2계층 `platform-security`는 내부 비공개 플랫폼이다.
- 서비스는 보통 `platform-security-bom`과 `platform-security-starter`를 사용한다.
- 운영 서비스는 `SecurityContextResolver`를 직접 제공한다.
- dev fallback resolver는 local/test에서만 opt-in으로 켠다.
- private publish는 GitHub Packages와 `v*` tag 기준으로 수행한다.

## 먼저 읽기

### 시작할 때

1. [아키텍처](./architecture.md)
2. [빠른 시작](./quickstart.md)
3. [모듈 가이드](./modules.md)

### auth-server에 붙일 때

1. [auth-server 적용 가이드](./auth-server-integration.md)
2. [설정](./configuration.md)

### 설정을 볼 때

1. [보안 모델](./security-model.md)
2. [설정](./configuration.md)

### 비공개 배포/소비를 볼 때

1. [Private publish and consumption](./private-publish.md)

### 문제가 생겼을 때

1. [트러블슈팅](./troubleshooting.md)