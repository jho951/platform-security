package io.github.jho951.platform.security.auth;

import com.auth.api.model.Principal;
import com.auth.oidc.OidcIdentity;
import com.auth.session.SessionStore;
import com.auth.spi.TokenService;
import io.github.jho951.platform.security.api.SecurityRequest;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PlatformSecurityContextResolversTest {
    @Test
    void anonymousResolverProducesAnonymousContext() {
        var resolver = PlatformSecurityContextResolvers.anonymous();
        var context = resolver.resolve(new SecurityRequest(
                null,
                "127.0.0.1",
                "/health",
                "GET",
                Map.of(),
                Instant.parse("2026-01-01T00:00:00Z")
        ));

        assertFalse(context.authenticated());
        assertNotNull(context.attributes());
    }

    @Test
    void oauth2BridgeDelegatesToAuthModuleResolver() {
        OAuth2PrincipalBridge bridge = PlatformSecurityContextResolvers.oauth2Bridge(identity ->
                new Principal(identity.getProvider() + ":" + identity.getProviderUserId())
        );

        PlatformAuthenticatedPrincipal principal = bridge.resolve(new PlatformOAuth2UserIdentity(
                "github",
                "42",
                "user@example.com",
                "User",
                Map.of()
        ));

        assertEquals("github:42", principal.userId());
    }

    @Test
    void hybridIssuerIssuesTokensAndSession() {
        TokenService tokenService = tokenService();
        InMemorySessionStore sessionStore = new InMemorySessionStore();
        TokenIssuanceCapability issuer = PlatformSecurityContextResolvers.hybridIssuer(tokenService, sessionStore);

        PlatformTokenBundle bundle = issuer.issue(new PlatformAuthenticatedPrincipal("user-1"));

        assertEquals("access-user-1", bundle.accessToken());
        assertEquals("refresh-user-1", bundle.refreshToken());
        assertTrue(bundle.sessionId() != null && sessionStore.find(bundle.sessionId()).isPresent());
    }

    @Test
    void defaultOidcPrincipalMapperUsesConfiguredClaims() {
        io.github.jho951.platform.security.policy.PlatformSecurityProperties.OidcProperties properties =
                new io.github.jho951.platform.security.policy.PlatformSecurityProperties.OidcProperties();
        properties.setPrincipalClaim("email");
        properties.setAuthoritiesClaim("groups");
        properties.setAuthorityPrefix("ROLE_");

        DefaultOidcPrincipalMapper mapper = new DefaultOidcPrincipalMapper(properties);

        Principal principal = mapper.map(new OidcIdentity(
                "subject-1",
                "https://issuer.example.com",
                "platform-client",
                Map.of(
                        "email", "user@example.com",
                        "groups", java.util.List.of("USER", "ADMIN")
                )
        ));

        assertEquals("user@example.com", principal.getUserId());
        assertEquals(java.util.List.of("ROLE_USER", "ROLE_ADMIN"), principal.getAuthorities());
        assertEquals("https://issuer.example.com", principal.getAttributes().get("issuer"));
    }

    private TokenService tokenService() {
        return new TokenService() {
            @Override
            public String issueAccessToken(Principal principal) {
                return "access-" + principal.getUserId();
            }

            @Override
            public String issueRefreshToken(Principal principal) {
                return "refresh-" + principal.getUserId();
            }

            @Override
            public Principal verifyAccessToken(String token) {
                return new Principal(token);
            }

            @Override
            public Principal verifyRefreshToken(String token) {
                return new Principal(token);
            }
        };
    }

    private static final class InMemorySessionStore implements SessionStore {
        private final Map<String, Principal> sessions = new HashMap<>();

        @Override
        public void save(String sessionId, Principal principal) {
            sessions.put(sessionId, principal);
        }

        @Override
        public Optional<Principal> find(String sessionId) {
            return Optional.ofNullable(sessions.get(sessionId));
        }

        @Override
        public void revoke(String sessionId) {
            sessions.remove(sessionId);
        }
    }
}
