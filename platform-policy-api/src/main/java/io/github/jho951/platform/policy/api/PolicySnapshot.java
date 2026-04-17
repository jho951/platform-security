package io.github.jho951.platform.policy.api;

import java.time.Instant;
import java.util.Map;

/**
 * 여러 정책 값을 같은 시점의 읽기 결과로 전달하는 snapshot이다.
 */
public record PolicySnapshot(Map<String, String> values, Instant resolvedAt) {
    public PolicySnapshot {
        values = values == null ? Map.of() : Map.copyOf(values);
        resolvedAt = resolvedAt == null ? Instant.EPOCH : resolvedAt;
    }
}
