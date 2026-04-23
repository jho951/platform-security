package io.github.jho951.platform.security.compat;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityContextResolver;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.autoconfigure.PlatformSecurityAutoConfiguration;
import io.github.jho951.platform.security.auth.autoconfigure.PlatformSecurityAuthAdapterAutoConfiguration;
import io.github.jho951.platform.security.local.PlatformSecurityLocalSupportAutoConfiguration;
import io.github.jho951.platform.security.policy.SecurityAttributes;
import io.github.jho951.platform.security.ratelimit.autoconfigure.PlatformSecurityRateLimitAdapterAutoConfiguration;
import io.github.jho951.platform.security.web.SecurityIngressRequestFactory;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LegacySecurityCompatibilityAutoConfigurationTest {
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    ConfigurationPropertiesAutoConfiguration.class,
                    PlatformSecurityLocalSupportAutoConfiguration.class,
                    PlatformSecurityAuthAdapterAutoConfiguration.class,
                    PlatformSecurityRateLimitAdapterAutoConfiguration.class,
                    PlatformSecurityAutoConfiguration.class,
                    LegacySecurityCompatibilityAutoConfiguration.class
            ));

    @Test
    void legacySecretCompatUsesIngressContributorAndPlatformOwnedAuthenticationAdapter() {
        contextRunner
                .withPropertyValues(
                        "platform.security.local-support.enabled=true",
                        "platform.security.auth.runtime-resolver-enabled=true",
                        "platform.security.auth.legacy-secret.enabled=true",
                        "platform.security.auth.legacy-secret.secret=debug-secret"
                )
                .run(context -> {
                    SecurityIngressRequestFactory requestFactory = context.getBean(SecurityIngressRequestFactory.class);
                    SecurityRequest request = requestFactory.fromServlet(
                            new org.springframework.mock.web.MockHttpServletRequest("POST", "/permissions/internal/admin/verify") {{
                                addHeader("X-Internal-Request-Secret", "debug-secret");
                            }},
                            Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), java.time.ZoneOffset.UTC)
                    );

                    assertEquals("debug-secret", request.attributes().get("auth.internalRequestSecret"));

                    SecurityContextResolver resolver = context.getBean(SecurityContextResolver.class);
                    SecurityContext resolved = resolver.resolve(new SecurityRequest(
                            null,
                            "127.0.0.1",
                            "/permissions/internal/admin/verify",
                            "POST",
                            Map.of(
                                    SecurityAttributes.BOUNDARY, "INTERNAL",
                                    "auth.internalRequestSecret", "debug-secret"
                            ),
                            Instant.now()
                    ));

                    assertTrue(resolved.authenticated());
                    assertEquals("platform-internal-compatibility", resolved.principal());
                });
    }
}
