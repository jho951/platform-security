package io.github.jho951.platform.policy.api;

import java.util.Optional;

/**
 * platform 정책 값을 읽는 최소 계약이다.
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
}
