package io.github.jho951.platform.security.policyconfig;

import io.github.jho951.platform.policy.api.PolicyConfigSource;
import io.github.jho951.platform.security.ip.PlatformIpRuleSource;

import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * policy-config 값에서 IP guard rule을 읽어오는 rule source다.
 */
public final class PolicyConfigPlatformIpRuleSource implements PlatformIpRuleSource {
    private final PolicyConfigSource policyConfigSource;
    private final String policyKey;

    public PolicyConfigPlatformIpRuleSource(PolicyConfigSource policyConfigSource, String policyKey) {
        this.policyConfigSource = Objects.requireNonNull(policyConfigSource, "policyConfigSource");
        this.policyKey = Objects.requireNonNull(policyKey, "policyKey");
    }

    @Override
    public String loadRules() {
        String value = policyConfigSource.resolve(policyKey)
                .orElseThrow(() -> new IllegalStateException("Missing IP policy config: " + policyKey));
        return normalize(value);
    }

    private String normalize(String value) {
        if (value == null) return "";
        return Arrays.stream(value.split("[,\\n]"))
                .map(String::trim)
                .filter(rule -> !rule.isBlank())
                .collect(Collectors.joining("\n"));
    }
}
