# Quality Gates

CI 기본 게이트는 다음 명령이다.

```bash
./gradlew check
```

`check`는 다음을 함께 실행한다.

- unit/integration test
- `verifyPublishedSurface`
- `verifyStarterContract`
- `verifyStage5Contract`
- sample consumer smoke test

## Static analysis

필요한 최소 정적 분석만 유지한다.

- compile
- Checkstyle
- PMD

서비스 리팩터링과 무관한 스타일 규칙을 과하게 늘리지 않는다.

## Stage-5 contract

`verifyStage5Contract`는 아래를 기본 규칙으로 검증한다.

- starter와 optional add-on이 compile surface를 오염시키지 않는가
- 공식 문서가 ownership/quality gate를 포함하는가
- sample consumer가 service-owned glue 없이 공식 surface로 부팅되는가

## 배포 전 확인

```bash
./gradlew clean check
```
