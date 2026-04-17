package io.github.jho951.platform.security.api;

/**
 * allow/deny 보안 평가를 위한 최소 facade다.
 */
public interface SecurityPolicyService {
    /**
     * 요청을 평가하고 최종 verdict를 반환한다.
     *
     * @param request 정규화된 요청
     * @param context 해석된 인증 context
     * @return 등록된 policy 평가 이후의 최종 verdict
     */
    SecurityVerdict evaluate(SecurityRequest request, SecurityContext context);
}
