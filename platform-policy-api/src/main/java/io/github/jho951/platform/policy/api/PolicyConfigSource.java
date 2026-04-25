package io.github.jho951.platform.policy.api;

import java.util.Map;
import java.util.Optional;

/**
 * platform 정책 값을 읽는 stack 공통 계약이다.
 */
@FunctionalInterface
public interface PolicyConfigSource {
    /**
     * 정책 key에 대응하는 현재 값을 조회한다.
     *
     * @param key 정책 key
     * @return 현재 값이 있으면 값, 없으면 empty
     */
    Optional<String> resolve(String key);

    /**
     * @return 현재 source가 같은 시점의 정책 snapshot을 제공하면 true
     */
    default boolean supportsSnapshot() {
        return false;
    }

    /**
     * @return 같은 시점의 정책 값 snapshot
     * @throws IllegalStateException snapshot을 지원하지 않는 source일 때
     */
    default Map<String, String> snapshot() {
        throw new IllegalStateException("PolicyConfigSource does not support snapshots");
    }

}
