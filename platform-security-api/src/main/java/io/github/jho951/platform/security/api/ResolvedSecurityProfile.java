package io.github.jho951.platform.security.api;

import java.util.List;
import java.util.Objects;

/**
 * 한 요청에 대해 platform-security가 해석한 보안 profile 스냅샷이다.
 *
 * <p>boundary, 매칭된 boundary pattern, client type, auth mode를 함께 담아
 * 정책 판단과 감사 기록에서 같은 기준을 재사용할 수 있게 한다.</p>
 *
 * @param boundaryType 해석된 boundary. 예: PUBLIC, PROTECTED, ADMIN, INTERNAL
 * @param boundaryPatterns 요청 boundary에 매칭된 path pattern 목록
 * @param clientType 해석된 client 분류
 * @param authMode 요청에 선택된 인증 capability
 */
public record ResolvedSecurityProfile(
        String boundaryType,
        List<String> boundaryPatterns,
        String clientType,
        String authMode
) {
    public ResolvedSecurityProfile {
        boundaryType = requireText(boundaryType, "boundaryType").toUpperCase();
        boundaryPatterns = boundaryPatterns == null ? List.of() : List.copyOf(boundaryPatterns);
        clientType = requireText(clientType, "clientType").toUpperCase();
        authMode = requireText(authMode, "authMode").toUpperCase();
    }

    private static String requireText(String value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) throw new IllegalArgumentException(field + " must not be blank");
        return value.trim();
    }
}
