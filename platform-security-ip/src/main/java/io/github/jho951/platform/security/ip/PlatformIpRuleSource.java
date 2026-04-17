package io.github.jho951.platform.security.ip;

/**
 * IP guard rule 문자열을 공급하는 source 계약이다.
 */
public interface PlatformIpRuleSource {
    /** @return 1계층 IP guard engine에 전달할 raw rule 문자열 */
    String loadRules();
}
