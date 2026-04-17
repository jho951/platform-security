package io.github.jho951.platform.security.ip;

import com.ipguard.core.decision.Decision;
import com.ipguard.core.engine.IpGuardEngine;

import java.util.Objects;

/**
 * platform IP rule source를 1계층 {@link IpGuardEngine} 입력으로 변환해 평가한다.
 *
 * <p>rule 문자열이 바뀌면 engine을 다시 구성한다.</p>
 */
public final class PlatformIpGuardEvaluator {
    private final PlatformIpRuleSource ruleSource;
    private final boolean defaultAllow;

    private volatile String loadedRules;
    private volatile IpGuardEngine engine;

    public PlatformIpGuardEvaluator(PlatformIpRuleSource ruleSource, boolean defaultAllow) {
        this.ruleSource = Objects.requireNonNull(ruleSource, "ruleSource");
        this.defaultAllow = defaultAllow;
    }

    public Decision decide(String clientIp) {
        String rules = ruleSource.loadRules();
        String normalized = PlatformIpRuleNormalizer.normalizeForEngine(rules);
        IpGuardEngine current = engine;
        if (current == null || !normalized.equals(loadedRules)) {
            current = new IpGuardEngine(() -> normalized, defaultAllow);
            loadedRules = normalized;
            engine = current;
        }
        return current.decide(clientIp);
    }
}
