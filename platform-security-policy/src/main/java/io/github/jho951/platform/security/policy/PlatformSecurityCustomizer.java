package io.github.jho951.platform.security.policy;

/**
 * Spring 설정 바인딩 이후 platform-security 설정을 코드로 보정하는 hook이다.
 *
 * <p>서비스별 boundary, route quota, IP guard rule을 YAML 대신 코드로 합성해야 할 때
 * 사용한다.</p>
 */
public interface PlatformSecurityCustomizer {
    /**
     * platform-security 설정 객체를 수정한다.
     *
     * @param properties 바인딩과 role preset 적용이 끝난 설정
     */
    void customize(PlatformSecurityProperties properties);
}
