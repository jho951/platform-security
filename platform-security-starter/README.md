# platform-security-starter

`platform-security-starter`는 Spring Boot 서비스가 사용하는 단일 dependency entry point다.

## 책임

- `platform-security-autoconfigure`를 transitively 제공한다.
- 서비스가 BOM + starter 조합만으로 2계층 보안 파이프라인을 가져가게 한다.
- starter artifact임을 식별할 수 있는 marker class만 가진다.
- 역할 차이는 `platform.security.service-role-preset` 설정으로 선택한다.

## 책임 아님

- auto-configuration 구현
- filter 구현
- policy engine 구현
- auth-server/gateway-server 전용 설정

예:

```yaml
platform:
  security:
    service-role-preset: api-server
```

실제 Spring Boot 자동 구성은 `platform-security-autoconfigure`에 있다.
