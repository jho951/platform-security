# Private Publish And Consumption

`platform-security`는 private GitHub Packages로 배포한다.

```text
platform-security
-> 내부 서비스용 private GitHub Packages
```

## 배포하는 것

3계층 서비스가 소비하거나 starter가 내부에서 쓰는 모듈을 배포한다.

```text
platform-security-bom
platform-security-starter
platform-security-client
platform-security-local-support
platform-security-test-support
platform-security-governance-bridge
platform-security-policyconfig-bridge

platform-security-policy
platform-security-api
platform-security-core
platform-security-auth
platform-security-ip
platform-security-rate-limit
platform-security-web
platform-security-autoconfigure
platform-security-issuer-autoconfigure
platform-security-internal-autoconfigure
platform-policy-api
```

`platform-security-policyconfig-bridge`는 `platform-policy-api`의 `PolicyConfigSource`를 공식 타입으로 소비한다.

배포하지 않는 것:

```text
platform-security-sample-consumer
```

## GitHub Actions 배포

tag를 push하면 publish workflow가 돈다.

```bash
git tag v1.1.0
git push origin v1.1.0
```

version은 tag에서 계산한다.

```text
v1.1.0
-> release_version=1.1.0
```

workflow 권한:

```yaml
permissions:
  contents: read
  packages: write
```

publish command:

```bash
./gradlew clean test publish \
  -Prelease_version="${VERSION}" \
  -PgithubPackagesUrl="https://maven.pkg.github.com/jho951/platform-security" \
  -PgithubPackagesUsername="${GITHUB_ACTOR}" \
  -PgithubPackagesToken="${GITHUB_TOKEN}"
```

## 로컬 배포

로컬에서 배포하려면 `write:packages` 권한이 있는 PAT가 필요하다.

```bash
export GITHUB_ACTOR=jho951
export GITHUB_TOKEN=<write:packages 권한이 있는 PAT>

./gradlew clean test publish \
  -Prelease_version=1.1.0 \
  -PgithubPackagesUrl=https://maven.pkg.github.com/jho951/platform-security \
  -PgithubPackagesUsername="$GITHUB_ACTOR" \
  -PgithubPackagesToken="$GITHUB_TOKEN"
```

권장 PAT 권한:

```text
write:packages
read:packages
repo          # private repo 접근이 필요할 때
```

## 소비 서비스 설정

3계층 서비스는 GitHub Packages repository와 credential을 설정한다.

```gradle
repositories {
    mavenCentral()
    maven {
        url = uri("https://maven.pkg.github.com/jho951/platform-security")
        credentials {
            username = findProperty("githubPackagesUsername") ?: System.getenv("GITHUB_ACTOR")
            password = findProperty("githubPackagesToken") ?: System.getenv("GITHUB_TOKEN")
        }
    }
}
```

dependency:

```gradle
dependencies {
    implementation platform("io.github.jho951.platform:platform-security-bom:1.1.0")
    implementation "io.github.jho951.platform:platform-security-starter"
}
```

## 소비 서비스 CI

다른 repo에서 private package를 읽을 때 기본 `secrets.GITHUB_TOKEN`으로 실패할 수 있다.  
그 경우 `read:packages`와 repo 접근 권한이 있는 PAT를 secret으로 둔다.

권장 secret 이름:

```text
GH_PACKAGES_TOKEN
```

workflow 예:

```yaml
env:
  GITHUB_ACTOR: jho951
  GITHUB_TOKEN: ${{ secrets.GH_PACKAGES_TOKEN }}
```

## 자주 나는 오류

| 오류 | 확인할 것 |
| --- | --- |
| `401 Unauthorized` | token이 비었는지, `read:packages` 권한이 있는지 |
| `403 Forbidden` | package 또는 private repo 접근 권한이 있는지 |
| `Could not find artifact` | version이 publish됐는지, repository URL이 맞는지 |

확인 명령:

```bash
echo "$GITHUB_ACTOR"
test -n "$GITHUB_TOKEN" && echo "token exists"
./gradlew dependencyInsight --dependency platform-security-starter
```
