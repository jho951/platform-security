# Documentation

## 핵심 기준

- 운영에서는 dev fallback을 쓰지 않는다.
- 운영에서는 `SecurityContextResolver`가 없으면 기동 실패한다그리.
- 운영에서는 trusted proxy CIDR과 공유 `RateLimiter`를 명시한다.
- governance audit을 쓰는 서비스는 bridge 모듈로 security verdict를 같은 audit 체계에 남긴다.

## 읽는 순서

| 목적 | 문서 |
| --- | --- |
| 2계층/3계층 책임 경계 이해 | [architecture.md](./architecture.md) |
| 어떤 starter를 써야 하는지 확인 | [modules.md](./modules.md) |
| Spring Boot 서비스에 붙이기 | [quickstart.md](./quickstart.md) |
| `platform.security.*` 설정 확인 | [configuration.md](./configuration.md) |
| 런타임 평가 순서와 header 계약 확인 | [security-model.md](./security-model.md) |
| override/SPI 확장 | [extension-guide.md](./extension-guide.md) |
| private publish와 소비 설정 | [private-publish.md](./private-publish.md) |
| 장애 대응 | [troubleshooting.md](./troubleshooting.md) |

