# Consumer Conformance

`platform-security-sample-consumer`는 공식 3계층 consumer conformance test다.

## 보장해야 하는 것

- 서비스는 `platform-security-starter`만으로 기본 runtime을 부팅할 수 있어야 한다.
- domain authorization은 3계층 책임으로 남고, platform은 boundary/auth/rate-limit만 판정해야 한다.
- raw auth bean과 raw rate limiter를 연결해야 할 때만 공식 bridge starter를 추가한다.
- custom policy bean은 `SecurityPolicyService` 전체 교체 없이 additive하게 합성되어야 한다.
- custom ingress attribute contributor와 failure writer는 공식 surface로만 확장되어야 한다.
- service-owned glue filter 없이 sample consumer가 현재 public contract만으로 동작해야 한다.

## 실행

```bash
./gradlew :platform-security-sample-consumer:test
```

루트 `./gradlew check`는 이 conformance test를 `verifyConsumerConformance`를 통해 기본 gate에 포함한다.

공식 재사용 fixture artifact는 `platform-security-test-support`다.
