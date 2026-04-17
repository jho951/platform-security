package io.github.jho951.platform.security.policy;

import java.util.List;
import java.util.Objects;

/**
 * 선택된 service role preset을 실제 platform-security 기본 설정으로 변환한다.
 *
 * <p>starter가 제공한 role은 여기서 boundary 기본값, auth mode, 허용 credential 조합으로
 * 확장된다. 사용자가 명시한 설정은 가능한 한 유지한다.</p>
 */
public final class PlatformSecurityPresetApplier {
    public void apply(PlatformSecurityProperties properties) {
        Objects.requireNonNull(properties, "properties");
        if (!properties.isEnabled()) {
            return;
        }
        ServiceRolePreset preset = properties.getServiceRolePreset();
        if (preset == null || preset == ServiceRolePreset.GENERAL) {
            return;
        }
        switch (preset) {
            case EDGE -> applyEdge(properties);
            case ISSUER -> applyIssuer(properties);
            case RESOURCE_SERVER -> applyResourceServer(properties);
            case INTERNAL_SERVICE -> applyInternalService(properties);
            case GENERAL -> {
            }
        }
    }

    private void applyEdge(PlatformSecurityProperties properties) {
        addCommonBoundaries(properties);
        ensureAuthDefaults(properties.getAuth(), AuthMode.HYBRID);
    }

    private void applyIssuer(PlatformSecurityProperties properties) {
        addCommonBoundaries(properties);
        ensureAuthDefaults(properties.getAuth(), AuthMode.HYBRID);
    }

    private void applyResourceServer(PlatformSecurityProperties properties) {
        addCommonBoundaries(properties);
        ensureAuthDefaults(properties.getAuth(), AuthMode.JWT);
        if (!properties.getAuth().isAllowSessionForBrowserConfigured()) {
            properties.getAuth().applyAllowSessionForBrowser(false);
        }
    }

    private void applyInternalService(PlatformSecurityProperties properties) {
        PlatformSecurityProperties.BoundaryPolicyProperties boundary = properties.getBoundary();
        if (boundary.getInternalPaths().isEmpty()) {
            boundary.getInternalPaths().add("/**");
        }
        ensureAuthDefaults(properties.getAuth(), AuthMode.HYBRID);
        if (!properties.getAuth().isAllowSessionForBrowserConfigured()) {
            properties.getAuth().applyAllowSessionForBrowser(false);
        }
        if (!properties.getAuth().isAllowApiKeyForApiConfigured()) {
            properties.getAuth().applyAllowApiKeyForApi(false);
        }
        if (!properties.getAuth().isAllowHmacForApiConfigured()) {
            properties.getAuth().applyAllowHmacForApi(false);
        }
        if (!properties.getAuth().isAllowOidcForApiConfigured()) {
            properties.getAuth().applyAllowOidcForApi(false);
        }
        if (!properties.getAuth().isServiceAccountEnabledConfigured()) {
            properties.getAuth().applyServiceAccountEnabled(true);
        }
        if (!properties.getAuth().isInternalTokenEnabledConfigured()) {
            properties.getAuth().applyInternalTokenEnabled(true);
        }
    }

    private void addCommonBoundaries(PlatformSecurityProperties properties) {
        PlatformSecurityProperties.BoundaryPolicyProperties boundary = properties.getBoundary();
        addIfAbsent(boundary.getPublicPaths(), "/health");
        addIfAbsent(boundary.getPublicPaths(), "/actuator/health");
        addIfAbsent(boundary.getProtectedPaths(), "/api/**");
        addIfAbsent(boundary.getAdminPaths(), "/admin/**");
        addIfAbsent(boundary.getInternalPaths(), "/internal/**");
    }

    private void ensureAuthDefaults(PlatformSecurityProperties.AuthProperties auth, AuthMode mode) {
        auth.setEnabled(true);
        if (!auth.isDefaultModeConfigured()) {
            auth.applyDefaultMode(mode);
        }
    }

    private void addIfAbsent(List<String> values, String value) {
        if (values.stream().noneMatch(existing -> value.equals(existing))) {
            values.add(value);
        }
    }
}
