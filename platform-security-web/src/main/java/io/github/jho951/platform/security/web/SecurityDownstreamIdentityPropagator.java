package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.api.SecurityEvaluationResult;
import io.github.jho951.platform.security.api.SecurityVerdict;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 평가 결과에서 downstream service로 전달할 표준 security header를 만든다.
 */
public final class SecurityDownstreamIdentityPropagator {
    /** servlet request attribute에 downstream header map을 저장할 때 쓰는 key다. */
    public static final String ATTR_DOWNSTREAM_HEADERS = "security.downstream.headers";

    /**
     * @param evaluationResult security 평가 결과
     * @return downstream header 묶음
     */
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

    /**
     * @param evaluationResult security 평가 결과
     * @return request attribute에 넣기 쉬운 header map
     */
    public Map<String, String> asAttributes(SecurityEvaluationResult evaluationResult) {
        return propagate(evaluationResult).asMap();
    }
}
