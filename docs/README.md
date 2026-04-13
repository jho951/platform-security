# Docs

이 디렉터리는 `platform-security`를 처음 쓰는 사람과 유지보수하는 사람이 필요한 문서를 모아둡니다.

## 문서 목록

1. [architecture.md](architecture.md)
2. [quickstart.md](quickstart.md)
3. [auth-server-integration.md](auth-server-integration.md)
4. [private-publish.md](private-publish.md)
5. [modules.md](modules.md)
6. [security-model.md](security-model.md)
7. [configuration.md](configuration.md)
8. [extension-guide.md](extension-guide.md)
9. [troubleshooting.md](troubleshooting.md)

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

## 읽는 법

- 1계층 공개 OSS 계약과 상위 기준은 `oss-contract`를 봅니다.
- 2계층 `platform-security`는 내부 비공개 플랫폼 레이어로 봅니다.
- 처음 사용하는 사람은 `아키텍처`, `빠른 시작`, `모듈 가이드` 순서로 보면 됩니다.
- 설정을 바꾸는 경우 `보안 모델`과 `설정`을 같이 봐야 합니다.
- 정책이나 adapter를 추가하는 경우 `확장 가이드`를 먼저 봅니다.
- 운영 적용을 확인하는 경우 `설정`, `보안 모델`, `트러블슈팅`을 함께 봅니다.
- auth-server 적용은 `auth-server 적용 가이드`를 먼저 봅니다.
- GitHub Packages 문제는 `Private publish and consumption`을 먼저 봅니다.
