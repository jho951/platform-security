# Release Notes

## Unreleased

### Reactive gateway hybrid integration

- `platform-security-hybrid-web-adapter` now exposes `PlatformSecurityReactiveGatewayIntegration` for WebFlux gateway assembly.
- hybrid mode registers a reactive gateway header authentication `WebFilter` and a `PlatformSecurityWebFilter` bundle when the application is reactive.

## 3.0.0 Changes

### Ports and runtime split

- public auth and rate-limit contracts now live in `platform-security-ports`.
- runtime/authentication/rate-limit orchestration classes now live in `platform-security-core`.
- `platform-security-autoconfigure`, `platform-security-issuer-autoconfigure`, and `platform-security-starter` now wire against `ports/core` instead of depending on adapter modules directly.

### Public contract alignment

- `platform-security-adapter-auth` public contracts now use platform-owned auth types such as `PlatformAuthenticatedPrincipal` and `PlatformOAuth2UserIdentity`.
- raw `com.auth.*` exposure is reduced from public contracts and kept behind adapter/helper boundaries where migration is still in progress.
- exposed `com.auth.*` dependencies remain promoted to `api` until the remaining helper surface is removed.

### Rate limit contract alignment

- `PlatformRateLimitPort` is now the primary service-facing rate-limit contract, while `PlatformRateLimitAdapter` remains only as an adapter marker around backing implementations.
- rate-limit policy and operational checks now depend on the platform adapter contract rather than raw layer1 SPI.

### Auto-configuration and gateway integration

- `PlatformSecurityAutoConfiguration` auth wiring now uses a platform-owned session support factory abstraction.
- `platform-security-hybrid-web-adapter` now exposes `PlatformSecurityGatewayIntegration` as the official gateway hybrid integration surface.

## 2.0.1 Changes

### IP guard configuration

- `ip-guard.trust-proxy` now defaults to `false`.
- Empty `ip-guard.trusted-proxy-cidrs` no longer trusts `X-Forwarded-For`.
- `admin-allow-cidrs` and `internal-allow-cidrs` are removed.
- Use `ip-guard.admin.rules` and `ip-guard.internal.rules`.
- `trusted-proxy-cidrs` accepts trusted proxy exact IP or CIDR values.
- `admin.rules` and `internal.rules` use ip-guard rule syntax, including CIDR and range rules.
- IP guard selection now documents the Profile-First, Path-Guard model: `ADMIN_CONSOLE` uses admin rules, `INTERNAL_SERVICE` uses internal rules, and normal protected requests do not use IP rules.
- `PlatformIpGuardFacade.fromRules(...)` was renamed to `fromIpGuardRules(...)`.

Migration:

```yaml
platform:
  security:
    ip-guard:
      trust-proxy: true
      trusted-proxy-cidrs:
        - <lb-or-ingress-cidr>
      admin:
        rules:
          - 10.0.0.0/8
      internal:
        rules:
          - 172.16.0.0/12
```

For local proxy testing:

```yaml
platform:
  security:
    ip-guard:
      trust-proxy: true
      trusted-proxy-cidrs:
        - 127.0.0.1
        - ::1
```
