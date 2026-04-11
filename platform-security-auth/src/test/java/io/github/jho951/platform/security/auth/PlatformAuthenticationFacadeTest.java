package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.policy.AuthMode;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PlatformAuthenticationFacadeTest {
    @Test
    void selectsSessionCapabilityForSessionMode() {
        AtomicReference<String> selected = new AtomicReference<>();
        PlatformAuthenticationFacade facade = new PlatformAuthenticationFacade(new RecordingResolver(selected));

        SecurityContext context = facade.resolve(new SecurityRequest(
                null,
                "127.0.0.1",
                "/api/orders",
                "GET",
                Map.of(
                        PlatformAuthenticationFacade.SESSION_ID_ATTRIBUTE, "session-1",
                        io.github.jho951.platform.security.policy.SecurityAttributes.AUTH_MODE, AuthMode.SESSION.name()
                ),
                Instant.parse("2026-01-01T00:00:00Z")
        ));

        assertEquals("session", selected.get());
        assertTrue(context.authenticated());
        assertEquals("session-user", context.principal());
    }

    @Test
    void selectsInternalCapabilityForInternalBoundary() {
        AtomicReference<String> selected = new AtomicReference<>();
        PlatformAuthenticationFacade facade = new PlatformAuthenticationFacade(new RecordingResolver(selected));

        SecurityContext context = facade.resolve(new SecurityRequest(
                null,
                "10.0.0.10",
                "/internal/sync",
                "POST",
                Map.of(
                        PlatformAuthenticationFacade.INTERNAL_TOKEN_ATTRIBUTE, "internal-token-1",
                        io.github.jho951.platform.security.policy.SecurityAttributes.BOUNDARY, "INTERNAL",
                        io.github.jho951.platform.security.policy.SecurityAttributes.AUTH_MODE, AuthMode.HYBRID.name()
                ),
                Instant.parse("2026-01-01T00:00:00Z")
        ));

        assertEquals("internal", selected.get());
        assertTrue(context.authenticated());
        assertEquals("internal-user", context.principal());
    }

    private static final class RecordingResolver implements AuthenticationCapabilityResolver {
        private final AtomicReference<String> selected;

        private RecordingResolver(AtomicReference<String> selected) {
            this.selected = selected;
        }

        @Override
        public AuthenticationCapability resolve(AuthMode authMode) {
            return resolve(authMode, false);
        }

        @Override
        public AuthenticationCapability resolve(AuthMode authMode, boolean internalService) {
            if (internalService) {
                return new AuthenticationCapability() {
                    @Override
                    public String name() {
                        return "internal";
                    }

                    @Override
                    public java.util.Optional<Principal> authenticate(SecurityRequest request) {
                        selected.set("internal");
                        return java.util.Optional.of(new Principal(
                                "internal-user",
                                List.of("INTERNAL"),
                                Map.of("scope", "internal")
                        ));
                    }
                };
            }
            return switch (authMode) {
                case SESSION -> new AuthenticationCapability() {
                    @Override
                    public String name() {
                        return "session";
                    }

                    @Override
                    public java.util.Optional<Principal> authenticate(SecurityRequest request) {
                        selected.set("session");
                        return java.util.Optional.of(new Principal(
                                "session-user",
                                List.of("USER"),
                                Map.of("source", "session")
                        ));
                    }
                };
                case JWT -> new AuthenticationCapability() {
                    @Override
                    public String name() {
                        return "jwt";
                    }

                    @Override
                    public java.util.Optional<Principal> authenticate(SecurityRequest request) {
                        selected.set("jwt");
                        return java.util.Optional.of(new Principal(
                                "jwt-user",
                                List.of("USER"),
                                Map.of("source", "jwt")
                        ));
                    }
                };
                case HYBRID -> new AuthenticationCapability() {
                    @Override
                    public String name() {
                        return "hybrid";
                    }

                    @Override
                    public java.util.Optional<Principal> authenticate(SecurityRequest request) {
                        selected.set("hybrid");
                        return java.util.Optional.of(new Principal(
                                "hybrid-user",
                                List.of("USER"),
                                Map.of("source", "hybrid")
                        ));
                    }
                };
                case NONE -> new AuthenticationCapability() {
                    @Override
                    public String name() {
                        return "none";
                    }

                    @Override
                    public java.util.Optional<Principal> authenticate(SecurityRequest request) {
                        selected.set("none");
                        return java.util.Optional.empty();
                    }
                };
            };
        }
    }
}
