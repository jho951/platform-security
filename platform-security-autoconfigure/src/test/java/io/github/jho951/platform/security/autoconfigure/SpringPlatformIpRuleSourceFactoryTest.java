package io.github.jho951.platform.security.autoconfigure;

import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties.IpRuleSourceType;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;

import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SpringPlatformIpRuleSourceFactoryTest {
    @Test
    void fileSourceReadsResourceLocation() throws Exception {
        java.nio.file.Path file = Files.createTempFile("ip-rules", ".txt");
        Files.writeString(file, "# comment\n10.0.0.0/8\n\n203.0.113.10/32\n");

        PlatformSecurityProperties.BoundaryIpGuardPolicy policy = new PlatformSecurityProperties.BoundaryIpGuardPolicy();
        policy.setSource(IpRuleSourceType.FILE);
        policy.setLocation(file.toUri().toString());

        SpringPlatformIpRuleSourceFactory factory = new SpringPlatformIpRuleSourceFactory(new DefaultResourceLoader());

        assertEquals("10.0.0.0/8\n203.0.113.10/32", factory.create(policy, java.util.List.of()).loadRules());
    }

    @Test
    void policyConfigSourceIsUnsupportedWithoutBridge() {
        PlatformSecurityProperties.BoundaryIpGuardPolicy policy = new PlatformSecurityProperties.BoundaryIpGuardPolicy();
        policy.setSource(IpRuleSourceType.POLICY_CONFIG);
        policy.setPolicyKey("security.ip-guard.admin.allow-cidrs");

        SpringPlatformIpRuleSourceFactory factory = new SpringPlatformIpRuleSourceFactory(new DefaultResourceLoader());

        assertThrows(IllegalStateException.class, () -> factory.create(policy, java.util.List.of()));
    }
}
