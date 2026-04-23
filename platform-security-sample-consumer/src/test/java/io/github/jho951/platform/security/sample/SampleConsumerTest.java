package io.github.jho951.platform.security.sample;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityContextResolver;
import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.SecurityPolicyService;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.auth.PlatformSessionIssuerPort;
import io.github.jho951.platform.security.auth.PlatformTokenIssuerPort;
import io.github.jho951.platform.security.hybrid.PlatformSecurityGatewayIntegration;
import io.github.jho951.platform.security.policy.AuthMode;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.ServiceRolePreset;
import io.github.jho951.platform.security.ratelimit.PlatformRateLimitPort;
import io.github.jho951.platform.security.web.SecurityFailureResponse;
import io.github.jho951.platform.security.web.SecurityFailureResponseWriter;
import io.github.jho951.platform.security.web.SecurityIngressContext;
import io.github.jho951.platform.security.web.SecurityRequestAttributeContributor;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
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
                    "platform.security.ip-guard.admin.rules[0]=10.0.0.0/8",
                    "platform.security.ip-guard.internal.rules[0]=10.0.0.0/8"
            );
    private final WebApplicationContextRunner hybridGatewayRunner = new WebApplicationContextRunner()
            .withConfiguration(autoConfigurations(
                    ConfigurationPropertiesAutoConfiguration.class,
                    "io.github.jho951.platform.security.autoconfigure.PlatformSecurityAutoConfiguration",
                    "io.github.jho951.platform.security.autoconfigure.PlatformSecurityHybridWebAdapterAutoConfiguration"
            ))
            .withBean(SecurityContextResolver.class, () -> request -> new SecurityContext(
                    true,
                    "gateway-user",
                    Set.of("ADMIN"),
                    Map.of()
            ))
            .withPropertyValues(
                    "platform.security.service-role-preset=edge",
                    "platform.security.ip-guard.admin.rules[0]=10.0.0.0/8",
                    "platform.security.ip-guard.internal.rules[0]=10.0.0.0/8"
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

    @Test
    void authBridgeStarterCreatesPlatformIssuerPortsFromRawAuthBeans() {
        new ApplicationContextRunner()
                .withConfiguration(autoConfigurations(
                        ConfigurationPropertiesAutoConfiguration.class,
                        "io.github.jho951.platform.security.auth.autoconfigure.PlatformSecurityAuthAdapterAutoConfiguration"
                ))
                .withBean(PlatformSecurityProperties.class, PlatformSecurityProperties::new)
                .withBean((Class<Object>) resolveAutoConfigurationClass("com.auth.spi.TokenService"),
                        () -> createNoopProxy(resolveAutoConfigurationClass("com.auth.spi.TokenService")))
                .withBean((Class<Object>) resolveAutoConfigurationClass("com.auth.session.SessionStore"),
                        () -> createNoopProxy(resolveAutoConfigurationClass("com.auth.session.SessionStore")))
                .run(context -> {
                    assertNull(context.getStartupFailure());
                    assertTrue(context.containsBean("platformTokenIssuerPort"));
                    assertTrue(context.containsBean("platformSessionIssuerPort"));
                    assertTrue(context.getBean(PlatformTokenIssuerPort.class) != null);
                    assertTrue(context.getBean(PlatformSessionIssuerPort.class) != null);
                });
    }

    @Test
    void rateLimitBridgeStarterCreatesPlatformRateLimitPortFromRawLimiter() {
        new ApplicationContextRunner()
                .withConfiguration(autoConfigurations(
                        ConfigurationPropertiesAutoConfiguration.class,
                        "io.github.jho951.platform.security.ratelimit.autoconfigure.PlatformSecurityRateLimitAdapterAutoConfiguration"
                ))
                .withBean((Class<Object>) resolveAutoConfigurationClass("io.github.jho951.ratelimiter.spi.RateLimiter"),
                        () -> createNoopProxy(resolveAutoConfigurationClass("io.github.jho951.ratelimiter.spi.RateLimiter")))
                .run(context -> {
                    assertNull(context.getStartupFailure());
                    assertTrue(context.containsBean("platformRateLimitPort"));
                    assertTrue(context.getBean(PlatformRateLimitPort.class) != null);
                });
    }

    @Test
    void customPolicyBeanIsComposedWithoutReplacingSecurityPolicyService() {
        apiServerRunner
                .withPropertyValues("platform.security.boundary.protected-paths[0]=/orders/**")
                .withBean(SecurityPolicy.class, () -> new SecurityPolicy() {
                    @Override
                    public String name() {
                        return "service-policy";
                    }

                    @Override
                    public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
                        if (request.path().startsWith("/orders/custom")) {
                            return SecurityVerdict.deny(name(), "blocked by service policy");
                        }
                        return SecurityVerdict.allow(name(), "allowed");
                    }
                })
                .run(context -> {
                    SecurityVerdict verdict = context.getBean(SecurityPolicyService.class).evaluate(
                            apiRequest("/orders/custom", Map.of("auth.accessToken", "token-1")),
                            authenticatedUser()
                    );

                    assertFalse(verdict.allowed());
                    assertEquals("service-policy", verdict.policy());
                });
    }

    @Test
    void customIngressContributorAddsLegacyAttributeWithoutServiceOwnedFilter() {
        apiServerRunner
                .withBean(SecurityRequestAttributeContributor.class, () -> new SecurityRequestAttributeContributor() {
                    @Override
                    public void contribute(SecurityIngressContext context, Map<String, String> attributes) {
                        String legacyCaller = context.headers().get("X-Legacy-Caller");
                        if (legacyCaller != null) {
                            attributes.put("auth.legacyCaller", legacyCaller);
                        }
                    }
                })
                .run(context -> {
                    var requestFactory = context.getBean(
                            resolveAutoConfigurationClass("io.github.jho951.platform.security.web.SecurityIngressRequestFactory")
                    );
                    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/documents/1");
                    request.addHeader("X-Legacy-Caller", "legacy-admin");

                    SecurityRequest resolved = invokeServletIngressFactory(requestFactory, request);

                    assertEquals("legacy-admin", resolved.attributes().get("auth.legacyCaller"));
                });
    }

    @Test
    void hybridGatewayUsesCustomFailureWriterFromWebApiSurface() {
        hybridGatewayRunner
                .withBean(SecurityFailureResponseWriter.class, RecordingFailureResponseWriter::new)
                .run(context -> {
                    assertNull(context.getStartupFailure());
                    PlatformSecurityGatewayIntegration integration = context.getBean(PlatformSecurityGatewayIntegration.class);
                    RecordingFailureResponseWriter writer = context.getBean(RecordingFailureResponseWriter.class);

                    assertSame(writer, integration.securityFailureResponseWriter());

                    MockHttpServletResponse response = new MockHttpServletResponse();
                    writer.write(new MockHttpServletRequest("GET", "/admin"), response,
                            new SecurityFailureResponse(418, "sample.denied", "sample"));

                    assertEquals(418, response.getStatus());
                    assertEquals("sample.denied", response.getHeader("X-Security-Code"));
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

    private static final class RecordingFailureResponseWriter implements SecurityFailureResponseWriter {
        @Override
        public void write(
                jakarta.servlet.http.HttpServletRequest request,
                jakarta.servlet.http.HttpServletResponse response,
                SecurityFailureResponse failure
        ) throws IOException {
            response.setStatus(failure.status());
            response.setHeader("X-Security-Code", failure.code());
            response.getWriter().write(failure.message() == null ? "" : failure.message());
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

    private static SecurityRequest invokeServletIngressFactory(Object requestFactory, MockHttpServletRequest request) {
        try {
            return (SecurityRequest) requestFactory.getClass()
                    .getMethod("fromServlet", jakarta.servlet.http.HttpServletRequest.class, java.time.Clock.class)
                    .invoke(requestFactory, request, java.time.Clock.systemUTC());
        } catch (ReflectiveOperationException exception) {
            throw new IllegalStateException("Failed to invoke SecurityIngressRequestFactory", exception);
        }
    }

    private static Object createNoopProxy(Class<?> interfaceType) {
        return java.lang.reflect.Proxy.newProxyInstance(
                SampleConsumerTest.class.getClassLoader(),
                new Class<?>[]{interfaceType},
                (proxy, method, args) -> {
                    Class<?> returnType = method.getReturnType();
                    if (returnType == Optional.class) {
                        return Optional.empty();
                    }
                    if (returnType == boolean.class) {
                        return false;
                    }
                    if (returnType == int.class) {
                        return 0;
                    }
                    if (returnType == long.class) {
                        return 0L;
                    }
                    if (returnType == double.class) {
                        return 0D;
                    }
                    if (returnType == float.class) {
                        return 0F;
                    }
                    if (returnType == String.class) {
                        return "sample";
                    }
                    return null;
                }
        );
    }
}
