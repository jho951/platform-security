package io.github.jho951.platform.security.auth;

import io.github.jho951.platform.security.api.SecurityRequest;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthServerSecurityContextResolverTest {
    @Test
    void resolvesSecurityContextFromAttributes() {
        AuthServerSecurityContextResolver resolver = new AuthServerSecurityContextResolver();
        SecurityRequest request = new SecurityRequest(
                null,
                "127.0.0.1",
                "/api",
                "read",
                Map.of(
                        AuthServerSecurityContextResolver.AUTHENTICATED_ATTRIBUTE, "true",
                        AuthServerSecurityContextResolver.PRINCIPAL_ATTRIBUTE, " user-1 ",
                        AuthServerSecurityContextResolver.ROLES_ATTRIBUTE, "USER,ADMIN",
                        "tenant", "t-1"
                ),
                Instant.parse("2026-01-01T00:00:00Z")
        );

        var context = resolver.resolve(request);

        assertTrue(context.authenticated());
        assertEquals("user-1", context.principal());
        assertEquals(Set.of("USER", "ADMIN"), context.roles());
        assertEquals("t-1", context.attributes().get("tenant"));
        assertFalse(context.attributes().containsKey(AuthServerSecurityContextResolver.AUTHENTICATED_ATTRIBUTE));
    }
}
