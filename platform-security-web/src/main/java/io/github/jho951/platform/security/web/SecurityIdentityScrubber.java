package io.github.jho951.platform.security.web;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

public final class SecurityIdentityScrubber {
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
            if (normalized.startsWith("x-security-") || normalized.startsWith("x-auth-")) {
                continue;
            }
            sanitized.put(key, Objects.toString(entry.getValue(), ""));
        }
        return Map.copyOf(sanitized);
    }
}
