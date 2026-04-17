package io.github.jho951.platform.security.api;

/**
 * 요청을 허용하거나 거부할 수 있는 단일 보안 규칙이다.
 *
 * <p>core service가 여러 policy를 조합한다. 각 policy는 인증, IP allow-list,
 * rate limit처럼 하나의 관심사에 집중하고 예측 가능하게 동작해야 한다.</p>
 */
public interface SecurityPolicy {
    /**
     * @return verdict와 감사 기록에 사용할 안정적인 policy 이름
     */
    String name();

    /**
     * 현재 요청과 context에 대해 이 policy를 평가한다.
     *
     * @param request 정규화된 요청
     * @param context 해석된 인증 context
     * @return policy verdict
     */
    SecurityVerdict evaluate(SecurityRequest request, SecurityContext context);
}
