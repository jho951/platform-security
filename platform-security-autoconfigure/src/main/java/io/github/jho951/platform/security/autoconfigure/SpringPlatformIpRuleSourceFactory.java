package io.github.jho951.platform.security.autoconfigure;

import io.github.jho951.platform.security.ip.CachingPlatformIpRuleSource;
import io.github.jho951.platform.security.ip.DefaultPlatformIpRuleSourceFactory;
import io.github.jho951.platform.security.ip.PlatformIpRuleSource;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties.IpRuleSourceType;
import org.springframework.core.io.ResourceLoader;

import java.util.List;
import java.util.Objects;

/**
 * Spring {@link ResourceLoader}를 사용해 FILE source IP rule을 읽을 수 있게 확장한 factory다.
 */
public class SpringPlatformIpRuleSourceFactory extends DefaultPlatformIpRuleSourceFactory {
    private final ResourceLoader resourceLoader;

    public SpringPlatformIpRuleSourceFactory(ResourceLoader resourceLoader) {
        this.resourceLoader = Objects.requireNonNull(resourceLoader, "resourceLoader");
    }

    @Override
    public PlatformIpRuleSource create(PlatformSecurityProperties.BoundaryIpGuardPolicy policy, List<String> legacyRules) {
        PlatformSecurityProperties.BoundaryIpGuardPolicy effective =
                policy == null ? new PlatformSecurityProperties.BoundaryIpGuardPolicy() : policy;
        if (effective.getSource() == IpRuleSourceType.FILE) {
            String location = trimToNull(effective.getLocation());
            if (location == null) {
                throw new IllegalStateException("IP rule source FILE requires a location");
            }
            return cache(new ResourceLocationPlatformIpRuleSource(resourceLoader, location), effective);
        }
        return super.create(effective, legacyRules);
    }

    protected PlatformIpRuleSource cache(
            PlatformIpRuleSource source,
            PlatformSecurityProperties.BoundaryIpGuardPolicy policy
    ) {
        return new CachingPlatformIpRuleSource(source, policy.getReloadTtl(), policy.isStaleWhileError());
    }

    protected String trimToNull(String value) {
        if (value == null) return null;
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
