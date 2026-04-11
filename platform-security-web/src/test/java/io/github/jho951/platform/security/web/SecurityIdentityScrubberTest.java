package io.github.jho951.platform.security.web;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class SecurityIdentityScrubberTest {
    private final SecurityIdentityScrubber scrubber = new SecurityIdentityScrubber();

    @Test
    void removesSecurityHeaders() {
        Map<String, String> sanitized = scrubber.scrub(Map.of(
                "x-security-token", "secret",
                "X-Auth-User", "user-1",
                "X-Auth-Session-Id", "session-1",
                "x-request-id", "req-1"
        ));

        assertNull(sanitized.get("X-Auth-User"));
        assertEquals("session-1", sanitized.get("X-Auth-Session-Id"));
        assertEquals("req-1", sanitized.get("x-request-id"));
    }
}
