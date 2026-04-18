package io.github.jho951.platform.security.ip;

import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.core.policy.IpAllowListPolicy;

import java.util.List;
import java.util.Objects;

/**
 * IP guard policy를 직접 호출해야 하는 코드에서 쓰는 작은 facade다.
 */
public final class PlatformIpGuardFacade {
    private final IpAllowListPolicy policy;

    public static PlatformIpGuardFacade fromIpGuardRules(List<String> rules, boolean defaultAllow) {
        return new PlatformIpGuardFacade(IpAllowListPolicy.fromIpGuardRules(rules, defaultAllow));
    }

    public SecurityVerdict evaluate(SecurityRequest request) {
        return policy.evaluate(request, null);
    }

    private PlatformIpGuardFacade(IpAllowListPolicy policy) {
        this.policy = Objects.requireNonNull(policy, "policy");
    }
}
