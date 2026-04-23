package io.github.jho951.platform.security.auth;

import io.github.jho951.platform.security.api.SecurityRequest;

import java.util.Optional;

/**
 * internal service 인증의 레거시/호환 credential을 platform-owned seam으로 흡수하는 확장 포인트다.
 *
 * <p>예를 들어 legacy shared secret이나 이전 세대 내부 헤더 proof를 서비스 filter가 직접 읽지 않고
 * platform capability가 fallback으로 소비하도록 연결할 때 사용한다.</p>
 */
public interface InternalServiceCompatibilityAuthenticationAdapter {
    Optional<PlatformAuthenticatedPrincipal> authenticate(SecurityRequest request);
}
