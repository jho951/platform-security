package io.github.jho951.platform.security.web;

final class SecurityFailureResponseJson {
    private SecurityFailureResponseJson() {
    }

    static String toJson(SecurityFailureResponse failure) {
        return "{\"code\":\""
                + escape(failure.code())
                + "\",\"message\":\""
                + escape(failure.message())
                + "\"}";
    }

    private static String escape(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        StringBuilder escaped = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> escaped.append("\\\"");
                case '\\' -> escaped.append("\\\\");
                case '\b' -> escaped.append("\\b");
                case '\f' -> escaped.append("\\f");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '\t' -> escaped.append("\\t");
                default -> {
                    if (c < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) c));
                    } else {
                        escaped.append(c);
                    }
                }
            }
        }
        return escaped.toString();
    }
}
