package io.github.jho951.platform.security.api;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

public record SecurityContext(
        boolean authenticated,
        String principal,
        Set<String> roles,
        Map<String, String> attributes
) {
    public SecurityContext {
        principal = principal == null || principal.isBlank() ? null : principal.trim();
        roles = roles == null ? Collections.emptySet() : Set.copyOf(roles);
        attributes = attributes == null ? Collections.emptyMap() : Map.copyOf(attributes);
    }
}
