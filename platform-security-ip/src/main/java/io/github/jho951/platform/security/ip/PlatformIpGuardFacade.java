package io.github.jho951.platform.security.ip;

import com.ipguard.core.engine.IpGuardEngine;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.core.policy.IpAllowListPolicy;

import java.util.Objects;

public final class PlatformIpGuardFacade {
    private final IpAllowListPolicy policy;

    public PlatformIpGuardFacade(IpGuardEngine ipGuardEngine) {
        this.policy = new IpAllowListPolicy(Objects.requireNonNull(ipGuardEngine, "ipGuardEngine"));
    }

    public SecurityVerdict evaluate(SecurityRequest request) {
        return policy.evaluate(request, null);
    }
}
