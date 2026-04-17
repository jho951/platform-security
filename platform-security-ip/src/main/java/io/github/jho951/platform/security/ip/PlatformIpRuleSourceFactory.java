package io.github.jho951.platform.security.ip;

import io.github.jho951.platform.security.policy.PlatformSecurityProperties;

import java.util.List;

/**
 * boundary별 IP guard 설정을 실행 가능한 rule source로 변환한다.
 */
public interface PlatformIpRuleSourceFactory {
    /**
     * IP guard policy 설정에 맞는 rule source를 만든다.
     *
     * @param policy boundary별 새 IP guard policy 설정
     * @param legacyRules deprecated allow CIDR 설정에서 넘어온 rule 목록
     * @return 실행 가능한 IP rule source
     */
    PlatformIpRuleSource create(PlatformSecurityProperties.BoundaryIpGuardPolicy policy, List<String> legacyRules);
}
