package io.github.jho951.platform.security.autoconfigure;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityContextResolver;
import io.github.jho951.platform.security.api.SecurityAuditPublisher;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.policy.ClientIpResolver;
import io.github.jho951.platform.security.policy.AuthMode;
import io.github.jho951.platform.security.policy.PlatformSecurityCustomizer;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.ServiceRolePreset;
import io.github.jho951.platform.security.policy.ServiceRolePresetProvider;
import io.github.jho951.platform.security.policy.SecurityBoundary;
import io.github.jho951.platform.security.policy.SecurityBoundaryResolver;
import io.github.jho951.platform.security.web.PlatformSecurityServletFilter;
import io.github.jho951.platform.security.web.SecurityDownstreamIdentityPropagator;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import com.auth.api.model.Principal;
import com.auth.session.SessionStore;
import com.auth.spi.TokenService;
import io.github.jho951.platform.security.auth.InternalTokenClaimsValidator;
import io.github.jho951.platform.security.local.PlatformSecurityLocalSupportAutoConfiguration;
import io.github.jho951.ratelimiter.core.RateLimitDecision;
import io.github.jho951.ratelimiter.spi.RateLimiter;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PlatformSecurityAutoConfigurationTest {
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    ConfigurationPropertiesAutoConfiguration.class,
                    PlatformSecurityAutoConfiguration.class
            ));
    private final ApplicationContextRunner localContextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    ConfigurationPropertiesAutoConfiguration.class,
                    PlatformSecurityLocalSupportAutoConfiguration.class,
                    PlatformSecurityAutoConfiguration.class
            ));

    @Test
    void registersBeansAndBindsPropertiesWithDevFallbackEnabled() {
        localContextRunner
                .withPropertyValues(
                        "platform.security.enabled=true",
                        "platform.security.local-support.enabled=true",
                        "platform.security.auth.dev-fallback.enabled=true",
                        "platform.security.ip-guard.trust-proxy=false",
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
    void failsFastWhenSecurityContextResolverIsMissing() {
        localContextRunner
                .withPropertyValues("platform.security.enabled=true")
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    assertTrue(context.getStartupFailure().getMessage().contains("No SecurityContextResolver configured"));
                });
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
                .run(context -> assertEquals(null, context.getStartupFailure()));
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
                    assertTrue(message.contains("production TokenService bean must be provided"));
                    assertTrue(message.contains("production SessionStore bean must be provided"));
                    assertTrue(message.contains("production InternalTokenClaimsValidator bean must be provided"));
                    assertTrue(message.contains("in-memory rate limiter is local/test only"));
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
                    assertTrue(message.contains("issuer services must provide a production TokenService bean"));
                    assertTrue(message.contains("issuer services with browser session support must provide a production SessionStore bean"));
                });
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
    void roleStarterProviderSelectsPresetWhenPropertyIsGeneral() {
        contextRunner
                .withBean(SecurityContextResolver.class, () -> request -> new SecurityContext(true, "resource", Set.of("USER"), Map.of()))
                .withBean(ServiceRolePresetProvider.class, () -> () -> ServiceRolePreset.RESOURCE_SERVER)
                .run(context -> {
                    PlatformSecurityProperties properties = context.getBean(PlatformSecurityProperties.class);
                    assertEquals(ServiceRolePreset.RESOURCE_SERVER, properties.getServiceRolePreset());
                    assertEquals(AuthMode.JWT, properties.getAuth().getDefaultMode());
                    assertEquals(false, properties.getAuth().isAllowSessionForBrowser());
                });
    }

    @Test
    void failsFastWhenMultipleRoleStartersAreSelected() {
        contextRunner
                .withBean("edgePresetProvider", ServiceRolePresetProvider.class, () -> () -> ServiceRolePreset.EDGE)
                .withBean("issuerPresetProvider", ServiceRolePresetProvider.class, () -> () -> ServiceRolePreset.ISSUER)
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    assertTrue(context.getStartupFailure().getMessage().contains("Only one platform-security role starter"));
                });
    }

    @Test
    void failsFastWhenRoleStarterConflictsWithExplicitPreset() {
        contextRunner
                .withBean(ServiceRolePresetProvider.class, () -> () -> ServiceRolePreset.EDGE)
                .withPropertyValues("platform.security.service-role-preset=issuer")
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    assertTrue(context.getStartupFailure().getMessage().contains("conflicts with selected starter"));
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
    void servletFilterPublishesToAllAuditPublishers() {
        List<String> auditPublishers = new java.util.ArrayList<>();

        contextRunner
                .withBean(SecurityContextResolver.class, () -> request -> new SecurityContext(true, "resource", Set.of("USER"), Map.of()))
                .withBean("firstAuditPublisher", SecurityAuditPublisher.class, () -> event -> auditPublishers.add("first"))
                .withBean("secondAuditPublisher", SecurityAuditPublisher.class, () -> event -> auditPublishers.add("second"))
                .run(context -> {
                    assertEquals(null, context.getStartupFailure());

                    PlatformSecurityServletFilter filter = context.getBean(PlatformSecurityServletFilter.class);
                    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/users");
                    request.setRemoteAddr("127.0.0.1");
                    MockHttpServletResponse response = new MockHttpServletResponse();

                    filter.doFilter(request, response, new MockFilterChain());

                    assertEquals(200, response.getStatus());
                    assertThat(auditPublishers)
                            .containsExactlyInAnyOrder("first", "second");
                    assertNotNull(request.getAttribute(SecurityDownstreamIdentityPropagator.ATTR_DOWNSTREAM_HEADERS));
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
