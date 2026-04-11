package io.github.jho951.platform.security.api;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

public record SecurityRequest(
        String subject,
        String clientIp,
        String path,
        String action,
        Map<String, String> attributes,
        Instant occurredAt
) {
    public SecurityRequest {
        subject = blankToNull(subject);
        clientIp = requireText(clientIp, "clientIp");
        path = requireText(path, "path");
        action = requireText(action, "action");
        attributes = attributes == null ? Collections.emptyMap() : Map.copyOf(attributes);
        occurredAt = occurredAt == null ? Instant.now() : occurredAt;
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String requireText(String value, String field) {
        if (value == null ) throw new IllegalArgumentException(field + " must not be blank");
		if (value.isBlank()) throw new IllegalArgumentException(field + " must not be blank");
        return value.trim();
    }
}
