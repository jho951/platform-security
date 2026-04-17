package io.github.jho951.platform.security.ip;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * 설정에 직접 적힌 IP rule 목록을 newline 문자열로 제공하는 rule source다.
 */
public final class InlinePlatformIpRuleSource implements PlatformIpRuleSource {
    private final List<String> rules;

    public InlinePlatformIpRuleSource(List<String> rules) {
        this.rules = rules == null ? List.of() : List.copyOf(rules);
    }

    @Override
    public String loadRules() {
        return rules.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(rule -> !rule.isBlank())
                .collect(Collectors.joining("\n"));
    }
}
