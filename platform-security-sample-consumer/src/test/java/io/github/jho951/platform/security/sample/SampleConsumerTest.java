package io.github.jho951.platform.security.sample;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityContextResolver;
import io.github.jho951.platform.security.api.SecurityPolicyService;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.policy.AuthMode;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.ServiceRolePreset;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SampleConsumerTest {
    private final ApplicationContextRunner apiServerRunner = new ApplicationContextRunner()
            .withConfiguration(autoConfigurations(
                    ConfigurationPropertiesAutoConfiguration.class,
                    "io.github.jho951.platform.security.autoconfigure.PlatformSecurityAutoConfiguration"
            ))
            .withBean(SecurityContextResolver.class, () -> request -> new SecurityContext(
                    true,
                    "user-1",
                    Set.of("USER"),
                    Map.of()
            ))
            .withPropertyValues(
                    "platform.security.service-role-preset=api-server",
                    "platform.security.ip-guard.admin-allow-cidrs[0]=10.0.0.0/8",
                    "platform.security.ip-guard.internal-allow-cidrs[0]=10.0.0.0/8"
            );

    @Test
    void apiServerConsumesRoleStarterWithoutManualPlatformAssembly() {
        apiServerRunner.run(context -> {
            assertNull(context.getStartupFailure());

            PlatformSecurityProperties properties = context.getBean(PlatformSecurityProperties.class);
            assertEquals(ServiceRolePreset.API_SERVER, properties.getServiceRolePreset());
            assertEquals(AuthMode.JWT, properties.getAuth().getDefaultMode());
            assertFalse(properties.getAuth().isAllowSessionForBrowser());

            SecurityVerdict verdict = context.getBean(SecurityPolicyService.class).evaluate(
                    apiRequest("/api/documents/1", Map.of("auth.accessToken", "token-1")),
                    authenticatedUser()
            );

            assertTrue(verdict.allowed(), () -> verdict.policy() + ":" + verdict.reason());
        });
    }

    @Test
    void serviceKeepsDomainAuthorizationOutsidePlatformSecurity() {
        apiServerRunner.run(context -> {
            SecurityVerdict platformVerdict = context.getBean(SecurityPolicyService.class).evaluate(
                    apiRequest("/api/documents/1", Map.of("auth.accessToken", "token-1")),
                    authenticatedUser()
            );

            assertTrue(platformVerdict.allowed(), () -> platformVerdict.policy() + ":" + platformVerdict.reason());
            assertFalse(new DocumentAccessPolicy().canUpdate("user-1", new Document("document-1", "owner-1")));
        });
    }

    private SecurityRequest apiRequest(String path, Map<String, String> attributes) {
        return new SecurityRequest(
                null,
                "127.0.0.1",
                path,
                "GET",
                attributes,
                Instant.parse("2026-01-01T00:00:00Z")
        );
    }

    private SecurityContext authenticatedUser() {
        return new SecurityContext(true, "user-1", Set.of("USER"), Map.of());
    }

    private record Document(String id, String ownerId) { }

    private static final class DocumentAccessPolicy {
        boolean canUpdate(String principal, Document document) {
            return document.ownerId().equals(principal);
        }
    }

    private static AutoConfigurations autoConfigurations(Object... autoConfigurationClasses) {
        return AutoConfigurations.of(Arrays.stream(autoConfigurationClasses)
                .map(SampleConsumerTest::resolveAutoConfigurationClass)
                .toArray(Class<?>[]::new));
    }

    private static Class<?> resolveAutoConfigurationClass(Object autoConfigurationClass) {
        if (autoConfigurationClass instanceof Class<?> type) {
            return type;
        }
        try {
            return Class.forName(String.valueOf(autoConfigurationClass));
        } catch (ClassNotFoundException exception) {
            throw new IllegalStateException(
                    "Auto-configuration class is not on the runtime classpath: " + autoConfigurationClass,
                    exception
            );
        }
    }
}
