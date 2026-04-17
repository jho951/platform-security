package io.github.jho951.platform.security.web;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * inbound header에서 downstream identity header와 불필요한 auth header를 제거한다.
 */
public final class SecurityIdentityScrubber {
    /**
     * 보안 평가에 넘겨도 되는 header만 남긴다.
     *
     * @param headers 원본 header map
     * @return scrub된 header map
     */
    public Map<String, String> scrub(Map<String, String> headers) {
        if (headers == null || headers.isEmpty()) {
            return Map.of();
        }

        Map<String, String> sanitized = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            String key = entry.getKey();
            if (key == null) {
                continue;
            }
            String normalized = key.trim().toLowerCase(Locale.ROOT);
            if (normalized.startsWith("x-security-")
                    || (normalized.startsWith("x-auth-") && !isInboundCredentialHeader(normalized))) {
                continue;
            }
            sanitized.put(key, Objects.toString(entry.getValue(), ""));
        }
        return Map.copyOf(sanitized);
    }

    private boolean isInboundCredentialHeader(String normalized) {
        return "x-auth-session-id".equals(normalized)
                || "x-auth-internal-token".equals(normalized)
                || "x-auth-api-key-id".equals(normalized)
                || "x-auth-api-key-secret".equals(normalized)
                || "x-auth-hmac-key-id".equals(normalized)
                || "x-auth-hmac-signature".equals(normalized)
                || "x-auth-hmac-timestamp".equals(normalized)
                || "x-auth-hmac-signed-headers".equals(normalized)
                || "x-auth-oidc-id-token".equals(normalized)
                || "x-auth-oidc-nonce".equals(normalized)
                || "x-auth-service-account-id".equals(normalized)
                || "x-auth-service-account-secret".equals(normalized);
    }
}
