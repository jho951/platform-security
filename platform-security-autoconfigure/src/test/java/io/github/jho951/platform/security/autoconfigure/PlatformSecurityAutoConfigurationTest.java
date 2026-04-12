package io.github.jho951.platform.security.autoconfigure;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityContextResolver;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.policy.ClientIpResolver;
import io.github.jho951.platform.security.policy.PlatformSecurityCustomizer;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.SecurityBoundary;
import io.github.jho951.platform.security.policy.SecurityBoundaryResolver;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PlatformSecurityAutoConfigurationTest {
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    ConfigurationPropertiesAutoConfiguration.class,
                    PlatformSecurityAutoConfiguration.class
            ));

    @Test
    void registersBeansAndBindsPropertiesWithDevFallbackEnabled() {
        contextRunner
                .withPropertyValues(
                        "platform.security.enabled=true",
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
        contextRunner
                .withPropertyValues("platform.security.enabled=true")
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    assertTrue(context.getStartupFailure().getMessage().contains("No SecurityContextResolver configured"));
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
        contextRunner
                .withBean(PlatformSecurityCustomizer.class, () -> properties -> properties.getIpGuard().setTrustProxy(false))
                .withPropertyValues("platform.security.auth.dev-fallback.enabled=true")
                .withPropertyValues("platform.security.ip-guard.trust-proxy=true")
                .run(context -> {
                    PlatformSecurityProperties properties = context.getBean(PlatformSecurityProperties.class);
                    assertEquals(false, properties.getIpGuard().isTrustProxy());
                });
    }
}
