package io.github.jho951.platform.security.auth;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * platform-security-auth 공개 계약이 사용하는 platform 소유 principal 모델이다.
 *
 * @param userId 안정적인 사용자 식별자
 * @param authorities 정규화된 authority 이름
 * @param attributes 추가 attribute
 */
public record PlatformAuthenticatedPrincipal(
        String userId,
        Set<String> authorities,
        Map<String, Object> attributes
) {
    public PlatformAuthenticatedPrincipal {
        userId = requireUserId(userId);
        authorities = authorities == null ? Collections.emptySet() : Set.copyOf(authorities);
        attributes = attributes == null ? Collections.emptyMap() : Map.copyOf(attributes);
    }

    public PlatformAuthenticatedPrincipal(String userId) {
        this(userId, Set.of(), Map.of());
    }

    private static String requireUserId(String userId) {
        if (userId == null || userId.isBlank()) {
            throw new IllegalArgumentException("userId must not be blank");
        }
        return userId.trim();
    }
}
