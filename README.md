# platform-security

## 빠른 사용

```gradle
dependencies {
    implementation platform("io.github.jho951.platform:platform-security-bom:1.0.5")
    implementation "io.github.jho951.platform:platform-security-*-starter"
}
```
### starter 종류:

- `platform-security-edge-starter`
- `platform-security-issuer-starter`
- `platform-security-resource-server-starter`
- `platform-security-internal-service-starter`

```java
@Bean
SecurityContextResolver securityContextResolver(CurrentUserResolver currentUserResolver) {
    return request -> {
        CurrentUser user = currentUserResolver.resolve(request);
        if (user == null) {
            return new SecurityContext(false, null, Set.of(), request.attributes());
        }
        return new SecurityContext(true, user.id(), user.roles(), request.attributes());
    };
}
```
## 검증

```bash
./gradlew test
```

## [문서](docs/README.md)
