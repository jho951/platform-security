package io.github.jho951.platform.security.core.policy;

import com.ipguard.core.decision.Decision;
import com.ipguard.core.engine.IpGuardEngine;
import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;

import java.util.List;
import java.util.Objects;

public final class IpAllowListPolicy implements SecurityPolicy {
    private final List<String> allowedIps;
    private final IpGuardEngine engine;

    public IpAllowListPolicy(List<String> allowedIps) {
        this.allowedIps = allowedIps == null ? List.of() : List.copyOf(allowedIps);
        this.engine = null;
    }

    public IpAllowListPolicy(IpGuardEngine engine) {
        this.allowedIps = List.of();
        this.engine = Objects.requireNonNull(engine, "engine");
    }

    @Override
    public String name() {
        return "ip-guard";
    }

    @Override
    public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
        Objects.requireNonNull(request, "request");
        if (engine != null) {
            Decision decision = engine.decide(request.clientIp());
            if (decision.allowed()) {
                return SecurityVerdict.allow(name(), decision.reason());
            }
            return SecurityVerdict.deny(name(), decision.reason());
        }
        if (allowedIps.isEmpty() || allowedIps.contains(request.clientIp())) {
            return SecurityVerdict.allow(name(), "ip allowed");
        }
        return SecurityVerdict.deny(name(), "ip not allowed: " + request.clientIp());
    }
}
