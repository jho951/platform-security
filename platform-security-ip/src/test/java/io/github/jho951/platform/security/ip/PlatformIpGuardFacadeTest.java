package io.github.jho951.platform.security.ip;

import io.github.jho951.platform.security.api.SecurityRequest;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PlatformIpGuardFacadeTest {
    @Test
    void fromRulesPreservesIpGuardIpv6RangeRules() {
        PlatformIpGuardFacade facade = PlatformIpGuardFacade.fromRules(List.of("2001:db8::1-2001:db8::f"), false);

        assertTrue(facade.evaluate(request("2001:db8::8")).allowed());
        assertFalse(facade.evaluate(request("2001:db8::10")).allowed());
    }

    @Test
    void fromRulesHonorsDefaultAllowWhenRulesAreEmpty() {
        PlatformIpGuardFacade facade = PlatformIpGuardFacade.fromRules(List.of(), true);

        assertTrue(facade.evaluate(request("10.0.0.10")).allowed());
    }

    private SecurityRequest request(String clientIp) {
        return new SecurityRequest(null, clientIp, "/", "IP_GUARD", Map.of(), Instant.EPOCH);
    }
}
