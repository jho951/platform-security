package io.github.jho951.platform.security.api;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class SecurityRequestTest {
    @Test
    void normalizesBlankValues() {
        SecurityRequest request = new SecurityRequest(
                "  user-1  ",
                " 127.0.0.1 ",
                " /api/demo ",
                " read ",
                Map.of("k", "v"),
                Instant.parse("2026-01-01T00:00:00Z")
        );

        assertEquals("user-1", request.subject());
        assertEquals("127.0.0.1", request.clientIp());
        assertEquals("/api/demo", request.path());
        assertEquals("read", request.action());
    }

    @Test
    void defaultContextCollectionsAreEmpty() {
        SecurityContext context = new SecurityContext(true, "   ", null, null);

        assertEquals(Set.of(), context.roles());
        assertEquals(Map.of(), context.attributes());
        assertNull(context.principal());
    }
}
