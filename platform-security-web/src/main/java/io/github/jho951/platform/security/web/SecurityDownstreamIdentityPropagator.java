package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.api.SecurityEvaluationResult;
import io.github.jho951.platform.security.api.SecurityVerdict;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public final class SecurityDownstreamIdentityPropagator {
    public static final String ATTR_DOWNSTREAM_HEADERS = "security.downstream.headers";

    public SecurityDownstreamHeaders propagate(SecurityEvaluationResult evaluationResult) {
        Objects.requireNonNull(evaluationResult, "evaluationResult");

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-Security-Boundary", evaluationResult.evaluationContext().profile().boundaryType());
        headers.put("X-Security-Client-Type", evaluationResult.evaluationContext().profile().clientType());
        headers.put("X-Security-Auth-Mode", evaluationResult.evaluationContext().profile().authMode());
        if (evaluationResult.evaluationContext().securityContext().principal() != null) {
            headers.put("X-Security-Principal", evaluationResult.evaluationContext().securityContext().principal());
        }
        headers.put("X-Security-Decision", evaluationResult.verdict().decision().name());
        headers.put("X-Security-Policy", evaluationResult.verdict().policy());
        String reason = evaluationResult.verdict().reason();
        if (reason != null) {
            headers.put("X-Security-Reason", reason);
        }
        return new SecurityDownstreamHeaders(headers);
    }

    public Map<String, String> asAttributes(SecurityEvaluationResult evaluationResult) {
        return propagate(evaluationResult).asMap();
    }
}
