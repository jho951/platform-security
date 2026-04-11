# Docs

이 디렉터리는 `platform-security`를 처음 쓰는 사람과 유지보수하는 사람이 필요한 문서를 모아둡니다.

## 문서 목록

1. [architecture.md](architecture.md)
2. [modules.md](modules.md)
3. [security-model.md](security-model.md)
4. [configuration.md](configuration.md)
5. [extension-guide.md](extension-guide.md)
6. [troubleshooting.md](troubleshooting.md)

## 먼저 읽기

### 시작할 때

1. [아키텍처](./architecture.md)
2. [모듈 가이드](./modules.md)
3. [확장 가이드](./extension-guide.md)

### 설정을 볼 때

1. [보안 모델](./security-model.md)
2. [설정](./configuration.md)

### 문제가 생겼을 때

1. [트러블슈팅](./troubleshooting.md)

## 읽는 법

- 1계층 공개 OSS 계약과 상위 기준은 `oss-contract`를 봅니다.
- 2계층 `platform-security`는 내부 비공개 플랫폼 레이어로 봅니다.
- 처음 사용하는 사람은 `아키텍처`, `모듈 가이드`, `확장 가이드` 순서로 보면 됩니다.
- 설정을 바꾸는 경우 `보안 모델`과 `설정`을 같이 봐야 합니다.
- 정책이나 adapter를 추가하는 경우 `확장 가이드`를 먼저 봅니다.
