package io.github.jho951.platform.security.api;

public interface SecurityEvaluationService {
    SecurityEvaluationResult evaluateResult(SecurityRequest request, SecurityContext context);
}
