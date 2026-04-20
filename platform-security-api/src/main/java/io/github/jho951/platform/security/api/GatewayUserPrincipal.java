package io.github.jho951.platform.security.api;

import java.security.Principal;
import java.util.UUID;

/**
 * Gateway가 전달한 사용자 컨텍스트를 platform-security 인증 주체로 표현한다.
 *
 * @param userId 사용자 식별자
 * @param status 사용자 상태 코드
 */
public record GatewayUserPrincipal(UUID userId, String status) implements Principal {
    @Override
    public String getName() {
        return userId.toString();
    }
}
