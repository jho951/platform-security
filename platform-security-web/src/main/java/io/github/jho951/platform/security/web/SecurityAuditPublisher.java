package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.api.SecurityEvaluationResult;

/**
 * security 평가 결과를 감사 시스템으로 넘기는 hook이다.
 *
 * <p>기본 구현은 no-op이며, governance bridge 모듈이 이 계약을 구현해 governance audit으로
 * 변환한다.</p>
 */
@FunctionalInterface
public interface SecurityAuditPublisher {
    /**
     * 평가 결과를 발행한다.
     *
     * @param evaluationResult security 평가 결과
     */
    void publish(SecurityEvaluationResult evaluationResult);

    /**
     * @return 아무 작업도 하지 않는 publisher
     */
    static SecurityAuditPublisher noop() {
        return evaluationResult -> {
        };
    }
}
