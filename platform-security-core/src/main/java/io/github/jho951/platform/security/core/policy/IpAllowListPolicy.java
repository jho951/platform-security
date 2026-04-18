package io.github.jho951.platform.security.core.policy;

import com.ipguard.core.decision.Decision;
import com.ipguard.core.engine.IpGuardEngine;
import com.ipguard.spi.RuleSource;
import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.policy.IpAddressMatcher;
import io.github.jho951.platform.security.policy.SecurityAttributes;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * IP allow-list를 평가하는 기본 보안 policy다.
 *
 * <p>{@link #IpAllowListPolicy(List)}는 exact IP 또는 CIDR만 처리한다.
 * range rule 같은 ip-guard rule 문법이 필요하면 {@link #fromIpGuardRules(List, boolean)}를 사용한다.</p>
 */
public final class IpAllowListPolicy implements SecurityPolicy {
    private final List<String> allowedIps;
    private final IpGuardEngine engine;

    public static IpAllowListPolicy fromIpGuardRules(List<String> rules, boolean defaultAllow) {
        RuleSource source = () -> rules == null
                ? ""
                : rules.stream()
                        .filter(Objects::nonNull)
                        .collect(Collectors.joining("\n"));

        return new IpAllowListPolicy(new IpGuardEngine(source, defaultAllow));
    }

    /**
     * exact IP 또는 CIDR allow-list를 만든다.
     *
     * <p>이 생성자는 ip-guard range rule 문법을 해석하지 않는다.</p>
     */
    public IpAllowListPolicy(List<String> allowedIps) {
        this.allowedIps = allowedIps == null ? List.of() : List.copyOf(allowedIps);
        this.engine = null;
    }

    IpAllowListPolicy(IpGuardEngine engine) {
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
        if (IpAddressMatcher.matchesAny(request.clientIp(), allowedIps)) return SecurityVerdict.allow(name(), "ip allowed");
        return SecurityVerdict.deny(name(), "ip not allowed: " + request.clientIp());
    }
}
