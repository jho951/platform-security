package io.github.jho951.platform.security.api;

public interface SecurityPolicyService {
    SecurityVerdict evaluate(SecurityRequest request, SecurityContext context);
}
