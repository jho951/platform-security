package io.github.jho951.platform.security.ip;

import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.ResolvedSecurityProfile;
import io.github.jho951.platform.security.policy.BoundaryIpPolicyProvider;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.SecurityBoundary;
import io.github.jho951.platform.security.policy.SecurityBoundaryType;

import java.util.List;
import java.util.Objects;

public final class DefaultBoundaryIpPolicyProvider implements BoundaryIpPolicyProvider {
    private final PlatformSecurityProperties.IpGuardProperties properties;

    public DefaultBoundaryIpPolicyProvider(PlatformSecurityProperties.IpGuardProperties properties) {
        this.properties = properties == null ? new PlatformSecurityProperties.IpGuardProperties() : properties;
    }

    @Override
    public SecurityPolicy resolve(SecurityBoundary boundary) {
        return resolve(boundary, null);
    }

    @Override
    public SecurityPolicy resolve(SecurityBoundary boundary, ResolvedSecurityProfile profile) {
        Objects.requireNonNull(boundary, "boundary");
        SecurityBoundaryType type = boundary.type();
        if (!properties.isEnabled() || type == SecurityBoundaryType.PUBLIC) {
            return new BoundaryAwareIpPolicy(boundary, properties, List.of());
        }
        if (type == SecurityBoundaryType.ADMIN) {
            return new BoundaryAwareIpPolicy(boundary, properties, properties.getAdminAllowCidrs());
        }
        if (type == SecurityBoundaryType.INTERNAL) {
            return new BoundaryAwareIpPolicy(boundary, properties, properties.getInternalAllowCidrs());
        }
        if (profile != null && "INTERNAL_SERVICE".equals(profile.clientType())) {
            return new BoundaryAwareIpPolicy(boundary, properties, properties.getInternalAllowCidrs());
        }
        if (profile != null && "ADMIN_CONSOLE".equals(profile.clientType())) {
            return new BoundaryAwareIpPolicy(boundary, properties, properties.getAdminAllowCidrs());
        }
        return new BoundaryAwareIpPolicy(boundary, properties, List.of());
    }
}
