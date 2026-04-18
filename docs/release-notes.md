# Release Notes

## 2.0.0 Breaking Changes

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
