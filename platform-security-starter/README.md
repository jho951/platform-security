# platform-security-starter

`platform-security-starter`는 역할 preset을 자동 선택하지 않는 일반 dependency entry point다.

## 책임

- `platform-security-autoconfigure`를 transitively 제공한다.
- 서비스가 BOM + starter 조합만으로 2계층 보안 파이프라인을 가져가게 한다.
- starter artifact임을 식별할 수 있는 marker class만 가진다.

## 책임 아님

- auto-configuration 구현
- filter 구현
- policy engine 구현
- 역할 preset 자동 선택
- auth-server/gateway-server 전용 설정

역할이 정해진 서비스는 다음 중 하나를 선택한다.

- `platform-security-edge-starter`
- `platform-security-issuer-starter`
- `platform-security-resource-server-starter`
- `platform-security-internal-service-starter`

실제 Spring Boot 자동 구성은 `platform-security-autoconfigure`에 있다.
