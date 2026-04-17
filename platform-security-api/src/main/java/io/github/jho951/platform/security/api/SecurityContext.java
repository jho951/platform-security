package io.github.jho951.platform.security.api;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * 보안 정책이 평가할 인증 상태다.
 *
 * <p>서비스의 user model 전체를 담지 않고, platform-security가 알아야 하는 인증 여부,
 * principal id, role, 비밀이 제거된 attribute만 유지한다.</p>
 *
 * @param authenticated 신뢰된 resolver가 요청을 인증했는지 여부
 * @param principal 안정적인 principal id. anonymous 요청이면 null
 * @param roles resolver가 정규화한 role 이름 목록
 * @param attributes 정책 평가에 필요한 추가 비밀 제거 context
 */
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
