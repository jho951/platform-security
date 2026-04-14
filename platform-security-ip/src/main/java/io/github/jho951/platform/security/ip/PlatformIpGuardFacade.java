package io.github.jho951.platform.security.ip;

import com.ipguard.core.engine.IpGuardEngine;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.core.policy.IpAllowListPolicy;

import java.util.List;
import java.util.Objects;

public final class PlatformIpGuardFacade {
    private final IpAllowListPolicy policy;

    public static PlatformIpGuardFacade fromRules(List<String> rules, boolean defaultAllow) {
        return new PlatformIpGuardFacade(IpAllowListPolicy.fromRules(rules, defaultAllow));
    }

    public PlatformIpGuardFacade(IpGuardEngine ipGuardEngine) {
        this(new IpAllowListPolicy(Objects.requireNonNull(ipGuardEngine, "ipGuardEngine")));
    }

    public SecurityVerdict evaluate(SecurityRequest request) {
        return policy.evaluate(request, null);
    }

    private PlatformIpGuardFacade(IpAllowListPolicy policy) {
        this.policy = Objects.requireNonNull(policy, "policy");
    }
}
