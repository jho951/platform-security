# platform-security

`platform-security`는 `auth`, `ip-guard`, `rate-limiter`를 조립하는 2계층 security platform이다.
1계층 OSS의 published artifact를 exact version으로 소비하고, 서비스가 붙는 보안 경계를 제공한다.

## 공개 좌표

- `io.github.jho951.platform:platform-security-bom`
- `io.github.jho951.platform:platform-security-policy`
- `io.github.jho951.platform:platform-security-auth`
- `io.github.jho951.platform:platform-security-ip`
- `io.github.jho951.platform:platform-security-rate-limit`
- `io.github.jho951.platform:platform-security-web`
- `io.github.jho951.platform:platform-security-autoconfigure`
- `io.github.jho951.platform:platform-security-starter`
- `io.github.jho951.platform:platform-security-test-support`

## 무엇을 제공하나

- 경계 분류
- 정책 프로필 선택
- client IP 해석
- auth 수행
- ip-guard 판정
- rate-limiter 판정
- 실패 응답 표준화
- downstream 신원 전달 표준화
- security integration API 제공

## 무엇을 제공하지 않나

- 로그인 / 회원가입 / 토큰 발급 비즈니스
- 사용자 계정 조회 비즈니스
- 서비스별 관리자 role 이름
- 특정 서비스 URL 하드코딩
- 특정 서비스 Redis key 규칙
- 1계층 OSS 내부 구현 재정의

## 모듈

- `platform-security-bom`
- `platform-security-policy`
- `platform-security-auth`
- `platform-security-ip`
- `platform-security-rate-limit`
- `platform-security-web`
- `platform-security-autoconfigure`
- `platform-security-starter`
- `platform-security-test-support`
- 호환 모듈: `platform-security-api`, `platform-security-core`, `platform-security-auth-adapter`, `platform-security-spring`, `platform-security-spring-boot-starter`, `platform-security-common-test`

## 핵심 정책

- 1계층 OSS의 Maven Central 배포본을 조합한다.
- `oss-contract`의 계층 규칙을 따른다.
- platform 내부에서 1계층 상세 구현을 다시 정의하지 않는다.
- 3계층 application은 policy와 configuration만 공급한다.
- `platform-security-core`는 순수 Java policy / engine 책임만 가진다.
- `platform-security-policy`는 공통 경계, 인증 모드, 클라이언트 타입, 공통 설정 모델을 가진다.
- `platform-security-auth`는 auth OSS 4개 모듈을 서비스용 인증 capability로 조립한다.
- `platform-security-ip`는 ip-guard OSS를 서비스 경계 IP 보호 capability로 조립한다.
- `platform-security-rate-limit`는 rate-limiter OSS를 서비스 요청 제한 capability로 조립한다.
- `platform-security-web`는 HTTP / Servlet 경계 적응만 가진다.
- `platform-security-auth-adapter`는 auth-server 헤더/클레임을 `SecurityContext`로 바꾼다.
- `platform-security-autoconfigure`는 Spring bean 조립을 제공한다.
- `platform-security-starter`는 최종 진입점이다.

## 외부 OSS

- `ip-guard`: `io.github.jho951:ip-guard-core:3.0.0`, `io.github.jho951:ip-guard-spi:3.0.0`
- `rate-limiter`: `io.github.jho951:rate-limiter-core:2.0.0`, `io.github.jho951:rate-limiter-spi:2.0.0`
- `auth`: `io.github.jho951:auth-core:3.0.0`, `io.github.jho951:auth-jwt:3.0.0`, `io.github.jho951:auth-session:3.0.0`, `io.github.jho951:auth-hybrid:3.0.0`

## 빌드

```bash
./gradlew test
```

## 문서

1. [docs/README.md](docs/README.md)
2. [docs/architecture.md](docs/architecture.md)
3. [docs/modules.md](docs/modules.md)
4. [docs/security-model.md](docs/security-model.md)
5. [docs/configuration.md](docs/configuration.md)
6. [docs/extension-guide.md](docs/extension-guide.md)
7. [docs/troubleshooting.md](docs/troubleshooting.md)
