package io.github.jho951.platform.security.hybrid;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityEvaluationResult;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.web.SecurityFailureResponse;

import java.util.Objects;
import java.util.function.BiFunction;
import java.util.function.UnaryOperator;

/**
 * gateway/edge가 low-level adapter 구현 대신 소비할 수 있는 hybrid runtime surface다.
 */
public final class HybridSecurityRuntime {
    private final UnaryOperator<SecurityRequest> boundaryResolver;
    private final BiFunction<SecurityRequest, SecurityContext, SecurityVerdict> verdictEvaluator;
    private final BiFunction<SecurityRequest, SecurityContext, SecurityEvaluationResult> resultEvaluator;
    private final BiFunction<SecurityRequest, SecurityContext, SecurityFailureResponse> failureEvaluator;

    public HybridSecurityRuntime(
            UnaryOperator<SecurityRequest> boundaryResolver,
            BiFunction<SecurityRequest, SecurityContext, SecurityVerdict> verdictEvaluator,
            BiFunction<SecurityRequest, SecurityContext, SecurityEvaluationResult> resultEvaluator,
            BiFunction<SecurityRequest, SecurityContext, SecurityFailureResponse> failureEvaluator
    ) {
        this.boundaryResolver = Objects.requireNonNull(boundaryResolver, "boundaryResolver");
        this.verdictEvaluator = Objects.requireNonNull(verdictEvaluator, "verdictEvaluator");
        this.resultEvaluator = Objects.requireNonNull(resultEvaluator, "resultEvaluator");
        this.failureEvaluator = Objects.requireNonNull(failureEvaluator, "failureEvaluator");
    }

    public SecurityRequest withResolvedBoundary(SecurityRequest request) {
        return boundaryResolver.apply(request);
    }

    public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
        return verdictEvaluator.apply(request, context);
    }

    public SecurityEvaluationResult evaluateResult(SecurityRequest request, SecurityContext context) {
        return resultEvaluator.apply(request, context);
    }

    public SecurityFailureResponse evaluateFailureResponse(SecurityRequest request, SecurityContext context) {
        return failureEvaluator.apply(request, context);
    }
}
