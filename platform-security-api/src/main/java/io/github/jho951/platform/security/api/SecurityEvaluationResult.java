package io.github.jho951.platform.security.api;

import java.util.Objects;

/**
 * 평가 입력 context와 최종 verdict를 함께 담는 결과 객체다.
 *
 * <p>감사 bridge는 이 타입을 사용해 decision뿐 아니라 그 결정을 만든 보안 profile도
 * 함께 기록한다.</p>
 *
 * @param evaluationContext 정책 입력 context
 * @param verdict 최종 보안 verdict
 */
public record SecurityEvaluationResult(
        SecurityEvaluationContext evaluationContext,
        SecurityVerdict verdict
) {
    public SecurityEvaluationResult {
        evaluationContext = Objects.requireNonNull(evaluationContext, "evaluationContext");
        verdict = Objects.requireNonNull(verdict, "verdict");
    }
}
