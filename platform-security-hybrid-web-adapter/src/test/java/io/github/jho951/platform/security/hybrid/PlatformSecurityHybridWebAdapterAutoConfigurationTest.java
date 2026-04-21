package io.github.jho951.platform.security.hybrid;

import io.github.jho951.platform.security.autoconfigure.PlatformSecurityAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class PlatformSecurityHybridWebAdapterAutoConfigurationTest {

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    ConfigurationPropertiesAutoConfiguration.class,
                    PlatformSecurityAutoConfiguration.class,
                    PlatformSecurityHybridWebAdapterAutoConfiguration.class
            ));

    @Test
    void disablesDefaultWebFiltersButKeepsSafeIngressBeans() {
        contextRunner.run(context -> {
            assertNotNull(context.getBean("securityIngressAdapter"));
            assertFalse(context.containsBean("securityServletFilter"));
            assertFalse(context.containsBean("gatewayHeaderAuthenticationFilter"));
        });
    }
}
