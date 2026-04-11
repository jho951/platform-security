package io.github.jho951.platform.security.api;

import java.util.Objects;

public record SecurityEvaluationResult(
        SecurityEvaluationContext evaluationContext,
        SecurityVerdict verdict
) {
    public SecurityEvaluationResult {
        evaluationContext = Objects.requireNonNull(evaluationContext, "evaluationContext");
        verdict = Objects.requireNonNull(verdict, "verdict");
    }
}
