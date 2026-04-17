package io.github.jho951.platform.security.policy;

import java.util.List;
import java.util.Objects;

/**
 * 요청 path가 속한 보안 boundary와 매칭 pattern 목록이다.
 *
 * @param type boundary type
 * @param patterns boundary를 결정한 path pattern 목록
 */
public record SecurityBoundary(SecurityBoundaryType type, List<String> patterns) {
    public SecurityBoundary {
        type = Objects.requireNonNull(type, "type");
        patterns = patterns == null ? List.of() : List.copyOf(patterns);
    }
}
