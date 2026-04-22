package io.github.jho951.platform.security.hybrid;

import io.github.jho951.platform.security.autoconfigure.PlatformSecurityAutoConfiguration;
import io.github.jho951.platform.security.autoconfigure.PlatformSecurityHybridWebAdapterAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PlatformSecurityHybridWebAdapterAutoConfigurationTest {

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    ConfigurationPropertiesAutoConfiguration.class,
                    PlatformSecurityAutoConfiguration.class,
                    PlatformSecurityHybridWebAdapterAutoConfiguration.class
            ));

    private final ReactiveWebApplicationContextRunner reactiveContextRunner = new ReactiveWebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    ConfigurationPropertiesAutoConfiguration.class,
                    PlatformSecurityAutoConfiguration.class,
                    PlatformSecurityHybridWebAdapterAutoConfiguration.class
            ));

    @Test
    void exposesGatewayIntegrationSurfaceWhileDisablingDefaultRegistrations() {
        contextRunner.run(context -> {
            assertNotNull(context.getBean("securityIngressAdapter"));
            assertNotNull(context.getBean(PlatformSecurityGatewayIntegration.class));
            assertNotNull(context.getBean("securityServletFilter"));
            assertNotNull(context.getBean("gatewayHeaderAuthenticationFilter"));
            assertFalse(context.containsBean("platformSecurityFilterChain"));
            PlatformSecurityGatewayIntegration integration = context.getBean(PlatformSecurityGatewayIntegration.class);
            assertNotNull(integration.platformSecurityServletFilter());
            assertNotNull(integration.securityIngressAdapter());
            assertTrue(integration.securityFailureResponseWriter() != null);
        });
    }

    @Test
    void exposesReactiveGatewayIntegrationSurfaceWhileDisablingDefaultRegistrations() {
        reactiveContextRunner.run(context -> {
            assertNotNull(context.getBean("securityIngressAdapter"));
            assertNotNull(context.getBean(PlatformSecurityReactiveGatewayIntegration.class));
            assertNotNull(context.getBean("securityWebFilter"));
            assertNotNull(context.getBean("reactiveGatewayHeaderAuthenticationWebFilter"));
            assertFalse(context.containsBean("platformSecurityFilterChain"));
            assertFalse(context.containsBean("securityServletFilter"));
            PlatformSecurityReactiveGatewayIntegration integration =
                    context.getBean(PlatformSecurityReactiveGatewayIntegration.class);
            assertNotNull(integration.platformSecurityWebFilter());
            assertNotNull(integration.gatewayHeaderAuthenticationWebFilter());
            assertNotNull(integration.securityIngressAdapter());
            assertTrue(integration.reactiveSecurityFailureResponseWriter() != null);
        });
    }
}
