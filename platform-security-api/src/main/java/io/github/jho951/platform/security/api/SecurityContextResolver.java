package io.github.jho951.platform.security.api;

/**
 * platform-security 요청을 정책 평가용 인증 context로 변환한다.
 *
 * <p>운영 서비스는 실제 인증 provider를 이 계약으로 연결하는 bean을 제공해야 한다.
 * platform 기본 fallback resolver는 local/test 용도다.</p>
 */
public interface SecurityContextResolver {
    /**
     * 요청의 principal, role, 안전한 attribute를 해석한다.
     *
     * @param request web, gateway, service code에서 정규화한 요청
     * @return 정책 평가에 사용할 보안 context
     */
    SecurityContext resolve(SecurityRequest request);
}
