# Documentation

이 디렉터리는 `platform-security`를 이해하고 적용하기 위한 문서다. 각 문서는 역할이 다르다.

## 처음 읽는 순서

1. [아키텍처](./architecture.md)
2. [모듈 가이드](./modules.md)
3. [빠른 시작](./quickstart.md)
4. [설정 레퍼런스](./configuration.md)
5. [보안 모델](./security-model.md)

## 목적별 문서

| 목적 | 문서 |
| --- | --- |
| 2계층/3계층 책임 경계 이해 | [architecture.md](./architecture.md) |
| 어떤 starter를 써야 하는지 확인 | [modules.md](./modules.md) |
| Spring Boot 서비스에 붙이기 | [quickstart.md](./quickstart.md) |
| `platform.security.*` 설정 확인 | [configuration.md](./configuration.md) |
| 런타임 평가 순서와 header 계약 확인 | [security-model.md](./security-model.md) |
| auth-server 적용 | [auth-server-integration.md](./auth-server-integration.md) |
| override/SPI 확장 | [extension-guide.md](./extension-guide.md) |
| private publish와 소비 설정 | [private-publish.md](./private-publish.md) |
| 장애 대응 | [troubleshooting.md](./troubleshooting.md) |

## 핵심 기준

- 2계층은 공통 인프라 운영 질서를 제공한다.
- 3계층은 서비스별 설정, resolver, provider, 도메인 로직을 제공한다.
- 역할 starter는 서비스 이름이 아니라 서비스 역할을 표현한다.
- 운영에서는 dev fallback을 쓰지 않는다.
- 운영에서는 `SecurityContextResolver`가 없으면 기동 실패한다.
