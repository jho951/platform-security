package io.github.jho951.platform.security.api;

public interface SecurityPolicy {
    String name();

    SecurityVerdict evaluate(SecurityRequest request, SecurityContext context);
}
