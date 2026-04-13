package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.api.SecurityEvaluationResult;

@FunctionalInterface
public interface SecurityAuditPublisher {
    void publish(SecurityEvaluationResult evaluationResult);

    static SecurityAuditPublisher noop() {
        return evaluationResult -> {
        };
    }
}
