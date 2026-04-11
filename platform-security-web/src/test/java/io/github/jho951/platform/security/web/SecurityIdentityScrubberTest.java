package io.github.jho951.platform.security.web;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SecurityIdentityScrubberTest {
    private final SecurityIdentityScrubber scrubber = new SecurityIdentityScrubber();

    @Test
    void removesSecurityHeaders() {
        Map<String, String> sanitized = scrubber.scrub(Map.of(
                "x-security-token", "secret",
                "X-Auth-User", "user-1",
                "x-request-id", "req-1"
        ));

        assertEquals(Map.of("x-request-id", "req-1"), sanitized);
    }
}
