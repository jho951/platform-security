package io.github.jho951.platform.security.web;

/**
 * 기본 failure response용 아주 작은 JSON writer다.
 */
public final class SecurityFailureResponseJson {
    private SecurityFailureResponseJson() {
    }

    public static String toJson(SecurityFailureResponse failure) {
        String message = failure.message();
        return "{\"status\":" + failure.status()
                + ",\"code\":\"" + escape(failure.code()) + "\""
                + ",\"message\":" + (message == null ? "null" : "\"" + escape(message) + "\"")
                + "}";
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
