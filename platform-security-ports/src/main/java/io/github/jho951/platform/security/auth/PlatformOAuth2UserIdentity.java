package io.github.jho951.platform.security.auth;

import java.util.Collections;
import java.util.Map;

/**
 * OAuth2 provider flow가 검증한 사용자 identity를 platform 소유 타입으로 표현한다.
 *
 * @param provider provider 이름
 * @param providerUserId provider 내부 사용자 식별자
 * @param email 선택적 email
 * @param displayName 선택적 display name
 * @param attributes provider 추가 attribute
 */
public record PlatformOAuth2UserIdentity(
        String provider,
        String providerUserId,
        String email,
        String displayName,
        Map<String, Object> attributes
) {
    public PlatformOAuth2UserIdentity {
        provider = requireText(provider, "provider");
        providerUserId = requireText(providerUserId, "providerUserId");
        email = blankToNull(email);
        displayName = blankToNull(displayName);
        attributes = attributes == null ? Collections.emptyMap() : Map.copyOf(attributes);
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value.trim();
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
