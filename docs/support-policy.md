# Support Policy

`platform-security`는 `release_version` 기준으로 versioned publish를 수행한다.

## Versioning

- public contract 변경은 문서와 release note를 먼저 갱신한다.
- breaking change는 minor/major release note에 명시한다.
- optional add-on과 test-support artifact도 같은 release train version을 따른다.

## Verification

배포 후보는 최소 다음을 통과해야 한다.

```bash
./gradlew clean check
```

## CI workflow

- `build.yml`은 `./gradlew clean check`를 stage-5 entry gate로 사용한다.
- `publish.yml`은 versioned publish 전에 같은 gate를 다시 통과시킨다.

## Support scope

- 공식 지원 surface는 starter, public API, policy model, 공식 bridge starter, official test-support artifact다.
- raw adapter implementation detail은 support contract가 아니다.
