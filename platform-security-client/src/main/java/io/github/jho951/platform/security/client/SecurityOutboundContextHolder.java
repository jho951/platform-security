package io.github.jho951.platform.security.client;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 현재 outbound 호출에 붙일 security header를 thread-bound context로 보관한다.
 */
public final class SecurityOutboundContextHolder {
    private static final ThreadLocal<Map<String, String>> HEADERS = new ThreadLocal<>();

    private SecurityOutboundContextHolder() {
    }

    public static void set(Map<String, String> headers) {
        if (headers == null || headers.isEmpty()) {
            HEADERS.remove();
            return;
        }
        HEADERS.set(Map.copyOf(headers));
    }

    public static Map<String, String> currentHeaders() {
        Map<String, String> headers = HEADERS.get();
        return headers == null ? Map.of() : headers;
    }

    public static void clear() {
        HEADERS.remove();
    }

    static Map<String, String> copyOf(Object attribute) {
        if (!(attribute instanceof Map<?, ?> source)) {
            return Map.of();
        }
        Map<String, String> headers = new LinkedHashMap<>();
        source.forEach((key, value) -> {
            if (key != null && value != null) {
                headers.put(String.valueOf(key), String.valueOf(value));
            }
        });
        return Map.copyOf(headers);
    }
}
