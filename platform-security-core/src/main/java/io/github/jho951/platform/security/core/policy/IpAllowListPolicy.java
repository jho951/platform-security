package io.github.jho951.platform.security.core.policy;

import com.ipguard.core.decision.Decision;
import com.ipguard.core.engine.IpGuardEngine;
import com.ipguard.spi.RuleSource;
import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.policy.SecurityAttributes;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * IP allow-list를 평가하는 기본 보안 policy다.
 *
 * <p>단순 문자열 목록 또는 1계층 {@link IpGuardEngine}을 받아 요청 client IP를 평가한다.</p>
 */
public final class IpAllowListPolicy implements SecurityPolicy {
    private final List<String> allowedIps;
    private final IpGuardEngine engine;

    public static IpAllowListPolicy fromRules(List<String> rules, boolean defaultAllow) {
        RuleSource source = () -> rules == null
                ? ""
                : rules.stream()
                        .filter(Objects::nonNull)
                        .collect(Collectors.joining("\n"));

        return new IpAllowListPolicy(new IpGuardEngine(source, defaultAllow));
    }

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
        if ("PUBLIC".equalsIgnoreCase(request.attributes().get(SecurityAttributes.BOUNDARY))) {
            return SecurityVerdict.allow(name(), "public boundary");
        }
        if (engine != null) {
            Decision decision = engine.decide(request.clientIp());
            if (decision.allowed()) return SecurityVerdict.allow(name(), decision.reason());
            return SecurityVerdict.deny(name(), decision.reason());
        }
        if (allowedIps.isEmpty()) return SecurityVerdict.allow(name(), "ip allowed");
        if (allowedIps.contains(request.clientIp())) return SecurityVerdict.allow(name(), "ip allowed");
        return SecurityVerdict.deny(name(), "ip not allowed: " + request.clientIp());
    }
}
