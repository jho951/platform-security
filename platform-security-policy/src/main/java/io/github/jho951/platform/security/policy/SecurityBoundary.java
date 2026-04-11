package io.github.jho951.platform.security.policy;

import java.util.List;
import java.util.Objects;

public record SecurityBoundary(SecurityBoundaryType type, List<String> patterns) {
    public SecurityBoundary {
        type = Objects.requireNonNull(type, "type");
        patterns = patterns == null ? List.of() : List.copyOf(patterns);
    }
}
