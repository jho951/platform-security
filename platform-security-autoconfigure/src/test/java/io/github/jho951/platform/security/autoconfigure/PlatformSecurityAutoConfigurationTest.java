package io.github.jho951.platform.security.autoconfigure;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.GatewayUserPrincipal;
import io.github.jho951.platform.security.api.SecurityContextResolver;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.auth.autoconfigure.PlatformSecurityAuthAdapterAutoConfiguration;
import io.github.jho951.platform.security.policy.ClientIpResolver;
import io.github.jho951.platform.security.policy.AuthMode;
import io.github.jho951.platform.security.policy.PlatformSecurityCustomizer;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.ServiceRolePreset;
import io.github.jho951.platform.security.policy.SecurityBoundary;
import io.github.jho951.platform.security.policy.SecurityBoundaryResolver;
import io.github.jho951.platform.security.ratelimit.autoconfigure.PlatformSecurityRateLimitAdapterAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import com.auth.api.model.Principal;
import com.auth.session.SessionStore;
import com.auth.spi.TokenService;
import io.github.jho951.platform.security.auth.InternalTokenClaimsValidator;
import io.github.jho951.platform.security.local.PlatformSecurityLocalSupportAutoConfiguration;
import io.github.jho951.ratelimiter.core.RateLimitDecision;
import io.github.jho951.ratelimiter.spi.RateLimiter;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PlatformSecurityAutoConfigurationTest {
    private static final Logger SPRING_CONTEXT_LOGGER =
            Logger.getLogger("org.springframework.context.support.AbstractApplicationContext");
    private static Level previousSpringContextLogLevel;

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    ConfigurationPropertiesAutoConfiguration.class,
                    PlatformSecurityAuthAdapterAutoConfiguration.class,
                    PlatformSecurityRateLimitAdapterAutoConfiguration.class,
                    PlatformSecurityAutoConfiguration.class
            ));
    private final ApplicationContextRunner localContextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    ConfigurationPropertiesAutoConfiguration.class,
                    PlatformSecurityLocalSupportAutoConfiguration.class,
                    PlatformSecurityAuthAdapterAutoConfiguration.class,
                    PlatformSecurityRateLimitAdapterAutoConfiguration.class,
                    PlatformSecurityAutoConfiguration.class
            ));

    @BeforeAll
    static void suppressExpectedContextRefreshWarnings() {
        previousSpringContextLogLevel = SPRING_CONTEXT_LOGGER.getLevel();
        SPRING_CONTEXT_LOGGER.setLevel(Level.SEVERE);
    }

    @AfterAll
    static void restoreContextRefreshWarnings() {
        SPRING_CONTEXT_LOGGER.setLevel(previousSpringContextLogLevel);
    }

    @Test
    void registersBeansAndBindsPropertiesWithDevFallbackEnabled() {
        localContextRunner
                .withPropertyValues(
                        "platform.security.enabled=true",
                        "platform.security.local-support.enabled=true",
                        "platform.security.auth.dev-fallback.enabled=true",
                        "platform.security.auth.allow-session-for-browser=false",
                        "platform.security.auth.allow-bearer-for-api=false"
                )
                .run(context -> {
                    assertNotNull(context.getBean(PlatformSecurityProperties.class));
                    assertNotNull(context.getBean(ClientIpResolver.class));
                    assertNotNull(context.getBean(SecurityContextResolver.class));
                    assertNotNull(context.getBean(SecurityBoundaryResolver.class));
                    assertNotNull(context.getBean("securityIngressRequestFactory"));

                    PlatformSecurityProperties properties = context.getBean(PlatformSecurityProperties.class);
                    assertEquals(false, properties.getIpGuard().isTrustProxy());
                    assertEquals(false, properties.getAuth().isAllowSessionForBrowser());
                    assertEquals(false, properties.getAuth().isAllowBearerForApi());
                    assertEquals(
                            "10.0.0.10",
                            context.getBean(ClientIpResolver.class).resolve("10.0.0.10", Map.of("X-Forwarded-For", "1.2.3.4"))
                    );
                });
    }

    @Test
    void registersSpringSecurityContextResolverByDefault() {
        localContextRunner
                .withPropertyValues("platform.security.enabled=true")
                .run(context -> {
                    assertEquals(null, context.getStartupFailure());
                    assertNotNull(context.getBean(SecurityContextResolver.class));
                });
    }

    @Test
    void platformJwtAuthorityConverterAddsRoleScopeAndStatusAuthorities() {
        PlatformSecurityProperties.AuthProperties properties = new PlatformSecurityProperties.AuthProperties();
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .subject("123e4567-e89b-12d3-a456-426614174000")
                .claim("role", "USER")
                .claim("scope", "internal")
                .claim("status", "A")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();

        Set<String> authorities = new PlatformJwtAuthorityConverter(properties)
                .convert(jwt)
                .stream()
                .map(org.springframework.security.core.GrantedAuthority::getAuthority)
                .collect(java.util.stream.Collectors.toSet());

        assertTrue(authorities.contains("ROLE_USER"));
        assertTrue(authorities.contains("SCOPE_internal"));
        assertTrue(authorities.contains("STATUS_A"));
        assertTrue(authorities.contains("STATUS_ACTIVE"));
    }

    @Test
    void gatewayHeaderAuthenticationFilterAuthenticatesGatewayUserHeaders() throws Exception {
        SecurityContextHolder.clearContext();
        try {
            PlatformSecurityProperties.GatewayHeaderProperties properties =
                    new PlatformSecurityProperties.GatewayHeaderProperties();
            properties.setEnabled(true);
            GatewayHeaderAuthenticationFilter filter = new GatewayHeaderAuthenticationFilter(properties);
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/users/me");
            request.addHeader("X-User-Id", "123e4567-e89b-12d3-a456-426614174000");
            request.addHeader("X-User-Status", "A");

            filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

            var authentication = SecurityContextHolder.getContext().getAuthentication();
            assertNotNull(authentication);
            assertEquals("123e4567-e89b-12d3-a456-426614174000", authentication.getName());
            assertTrue(authentication.getPrincipal() instanceof GatewayUserPrincipal);
            assertTrue(authentication.getAuthorities().stream()
                    .anyMatch(authority -> "STATUS_ACTIVE".equals(authority.getAuthority())));
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    @Test
    void failsFastWhenProductionPolicyIsViolated() {
        localContextRunner
                .withPropertyValues(
                        "platform.security.local-support.enabled=true",
                        "spring.profiles.active=prod",
                        "platform.security.auth.dev-fallback.enabled=true"
                )
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    assertTrue(context.getStartupFailure().getMessage().contains("operational policy violation"));
                    assertTrue(context.getStartupFailure().getMessage().contains("dev-fallback.enabled must be false"));
                });
    }

    @Test
    void productionProfileNameIsNotTreatedAsProductionByDefault() {
        localContextRunner
                .withPropertyValues(
                        "platform.security.local-support.enabled=true",
                        "spring.profiles.active=production",
                        "platform.security.auth.dev-fallback.enabled=true"
                )
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    assertTrue(context.getStartupFailure().getMessage().contains("operational policy violation"));
                });
    }

    @Test
    void failsFastWhenProductionUsesPlatformLocalFallbackBeans() {
        localContextRunner
                .withBean(SecurityContextResolver.class, () -> request -> new SecurityContext(true, "prod-user", Set.of("USER"), Map.of()))
                .withPropertyValues(
                        "platform.security.local-support.enabled=true",
                        "spring.profiles.active=prod",
                        "platform.security.auth.jwt-secret=prod-secret-prod-secret-prod-secret-prod-secret",
                        "platform.security.ip-guard.trusted-proxy-cidrs[0]=10.0.0.0/8",
                        "platform.security.ip-guard.admin.rules[0]=10.0.0.0/8",
                        "platform.security.ip-guard.internal.rules[0]=10.0.0.0/8"
                )
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    String message = context.getStartupFailure().getMessage();
                    assertTrue(message.contains("production PlatformTokenIssuerPort bean must be provided"));
                    assertTrue(message.contains("production PlatformSessionIssuerPort bean must be provided"));
                    assertTrue(message.contains("production InternalTokenClaimsValidator bean must be provided"));
                    assertTrue(message.contains("platform local rate limiter is local/test only"));
                });
    }

    @Test
    void failsFastWhenProductionIssuerDoesNotProvideTokenOrSessionStores() {
        contextRunner
                .withBean(SecurityContextResolver.class, () -> request -> new SecurityContext(true, "issuer", Set.of("USER"), Map.of()))
                .withBean(RateLimiter.class, () -> (key, permits, plan) -> RateLimitDecision.allow(plan.getCapacity()))
                .withBean(InternalTokenClaimsValidator.class, () -> (principal, request) -> principal != null)
                .withPropertyValues(
                        "spring.profiles.active=prod",
                        "platform.security.service-role-preset=issuer",
                        "platform.security.auth.jwt-secret=prod-secret-prod-secret-prod-secret-prod-secret",
                        "platform.security.ip-guard.trusted-proxy-cidrs[0]=10.0.0.0/8",
                        "platform.security.ip-guard.admin.rules[0]=10.0.0.0/8",
                        "platform.security.ip-guard.internal.rules[0]=10.0.0.0/8"
                )
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    String message = context.getStartupFailure().getMessage();
                    assertTrue(message.contains("issuer services must provide a production PlatformTokenIssuerPort bean"));
                    assertTrue(message.contains("issuer services with browser session support must provide a production PlatformSessionIssuerPort bean"));
                });
    }

    @Test
    void internalServicePresetAllowsDisabledIngressControlsInProduction() {
        contextRunner
                .withBean(SecurityContextResolver.class, () -> request -> new SecurityContext(true, "internal", Set.of("INTERNAL"), Map.of()))
                .withBean(InternalTokenClaimsValidator.class, () -> (principal, request) -> true)
                .withPropertyValues(
                        "spring.profiles.active=prod",
                        "platform.security.service-role-preset=internal-service",
                        "platform.security.auth.jwt-secret=prod-secret-prod-secret-prod-secret-prod-secret",
                        "platform.security.ip-guard.enabled=false",
                        "platform.security.rate-limit.enabled=false"
                )
                .run(context -> assertEquals(null, context.getStartupFailure()));
    }

    @Test
    void acceptsProductionPolicyWhenRequiredInputsAreProvided() {
        localContextRunner
                .withBean(SecurityContextResolver.class, () -> request -> new SecurityContext(true, "prod-user", Set.of("USER"), Map.of()))
                .withBean(RateLimiter.class, () -> (key, permits, plan) -> RateLimitDecision.allow(plan.getCapacity()))
                .withBean(SessionStore.class, InMemorySessionStore::new)
                .withBean(InternalTokenClaimsValidator.class, () -> (principal, request) -> principal != null)
                .withBean(TokenService.class, () -> new TokenService() {
                    @Override
                    public String issueAccessToken(com.auth.api.model.Principal principal) {
                        return "access";
                    }

                    @Override
                    public String issueRefreshToken(com.auth.api.model.Principal principal) {
                        return "refresh";
                    }

                    @Override
                    public com.auth.api.model.Principal verifyAccessToken(String token) {
                        return null;
                    }

                    @Override
                    public com.auth.api.model.Principal verifyRefreshToken(String token) {
                        return null;
                    }
                })
                .withPropertyValues(
                        "spring.profiles.active=prod",
                        "platform.security.auth.jwt-secret=prod-secret-prod-secret-prod-secret-prod-secret",
                        "platform.security.ip-guard.trusted-proxy-cidrs[0]=10.0.0.0/8",
                        "platform.security.ip-guard.admin.rules[0]=10.0.0.0/8",
                        "platform.security.ip-guard.internal.rules[0]=10.0.0.0/8"
                )
                .run(context -> {
                    assertEquals(null, context.getStartupFailure());
                    assertNotNull(context.getBean(SecurityContextResolver.class));
                });
    }

    @Test
    void serviceRolePresetAppliesCommonDefaultsBeforeCustomizers() {
        contextRunner
                .withBean(SecurityContextResolver.class, () -> request -> new SecurityContext(true, "issuer", Set.of("USER"), Map.of()))
                .withBean(PlatformSecurityCustomizer.class, () -> properties -> properties.getBoundary().getPublicPaths().add("/custom/public"))
                .withPropertyValues("platform.security.service-role-preset=issuer")
                .run(context -> {
                    PlatformSecurityProperties properties = context.getBean(PlatformSecurityProperties.class);
                    assertEquals(AuthMode.HYBRID, properties.getAuth().getDefaultMode());
                    assertTrue(properties.getBoundary().getProtectedPaths().contains("/api/**"));
                    assertTrue(properties.getBoundary().getPublicPaths().contains("/custom/public"));
                    assertTrue(properties.getRateLimit().getRoutes().isEmpty());
                });
    }

    @Test
    void serviceRolePresetPropertyAppliesApiServerDefaults() {
        contextRunner
                .withBean(SecurityContextResolver.class, () -> request -> new SecurityContext(true, "api-user", Set.of("USER"), Map.of()))
                .withPropertyValues("platform.security.service-role-preset=api-server")
                .run(context -> {
                    PlatformSecurityProperties properties = context.getBean(PlatformSecurityProperties.class);
                    assertEquals(ServiceRolePreset.API_SERVER, properties.getServiceRolePreset());
                    assertEquals(AuthMode.JWT, properties.getAuth().getDefaultMode());
                    assertEquals(false, properties.getAuth().isAllowSessionForBrowser());
                });
    }

    @Test
    void disabledConfigurationDoesNotRegisterSecurityBeans() {
        contextRunner
                .withPropertyValues("platform.security.enabled=false")
                .run(context -> {
                    assertEquals(false, context.containsBean("securityServletFilter"));
                    assertEquals(false, context.containsBean("securityWebFilter"));
                });
    }

    @Test
    void customBeansOverrideDefaults() {
        contextRunner
                .withBean(SecurityContextResolver.class, () -> request -> new SecurityContext(true, "override", Set.of("USER"), Map.of()))
                .withBean(SecurityBoundaryResolver.class, () -> request -> new SecurityBoundary(io.github.jho951.platform.security.policy.SecurityBoundaryType.ADMIN, List.of("/admin/**")))
                .run(context -> {
                    SecurityRequest request = new SecurityRequest(null, "127.0.0.1", "/admin/users", "GET", Map.of(), Instant.parse("2026-01-01T00:00:00Z"));
                    SecurityContextResolver resolver = context.getBean(SecurityContextResolver.class);
                    assertEquals("override", resolver.resolve(request).principal());
                    assertEquals(io.github.jho951.platform.security.policy.SecurityBoundaryType.ADMIN, context.getBean(SecurityBoundaryResolver.class).resolve(request).type());
                });
    }

    @Test
    void customizerAppliesToBoundProperties() {
        localContextRunner
                .withBean(PlatformSecurityCustomizer.class, () -> properties -> properties.getIpGuard().setTrustProxy(false))
                .withPropertyValues("platform.security.local-support.enabled=true")
                .withPropertyValues("platform.security.auth.dev-fallback.enabled=true")
                .withPropertyValues("platform.security.ip-guard.trust-proxy=true")
                .run(context -> {
                    PlatformSecurityProperties properties = context.getBean(PlatformSecurityProperties.class);
                    assertEquals(false, properties.getIpGuard().isTrustProxy());
                });
    }

    private static final class InMemorySessionStore implements SessionStore {
        @Override
        public void save(String sessionId, Principal principal) {
        }

        @Override
        public Optional<Principal> find(String sessionId) {
            return Optional.empty();
        }

        @Override
        public void revoke(String sessionId) {
        }
    }
}
