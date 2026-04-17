package io.github.jho951.platform.security.api;

/**
 * 요청을 평가하고 전체 context와 verdict를 반환한다.
 *
 * <p>감사에 필요한 상세 정보가 필요할 때 사용한다. allow/deny만 필요하면
 * {@link SecurityPolicyService}를 사용한다.</p>
 */
public interface SecurityEvaluationService {
    /**
     * 이미 해석된 security context로 요청을 평가한다.
     *
     * @param request 정규화된 요청
     * @param context 해석된 인증 context
     * @return 전체 평가 결과
     */
    SecurityEvaluationResult evaluateResult(SecurityRequest request, SecurityContext context);
}
