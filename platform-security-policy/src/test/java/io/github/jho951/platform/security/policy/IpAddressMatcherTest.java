package io.github.jho951.platform.security.policy;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IpAddressMatcherTest {
    @Test
    void matchesIpv4Cidr() {
        assertTrue(IpAddressMatcher.matches("10.1.2.3", "10.0.0.0/8"));
        assertFalse(IpAddressMatcher.matches("192.168.1.10", "10.0.0.0/8"));
    }

    @Test
    void matchesIpv6Cidr() {
        assertTrue(IpAddressMatcher.matches("2001:db8::8", "2001:db8::/64"));
        assertFalse(IpAddressMatcher.matches("2001:db9::8", "2001:db8::/64"));
    }

    @Test
    void matchesExactIp() {
        assertTrue(IpAddressMatcher.matches("::ffff:10.0.0.1", "10.0.0.1"));
        assertFalse(IpAddressMatcher.matches("10.0.0.2", "10.0.0.1"));
    }

    @Test
    void matchesAnySkipsInvalidRules() {
        assertTrue(IpAddressMatcher.matchesAny("10.1.2.3", List.of("invalid/", "10.0.0.0/8")));
        assertFalse(IpAddressMatcher.matchesAny("10.1.2.3", List.of("invalid/", "192.168.0.0/16")));
    }

    @Test
    void rejectsHostNamesAndAmbiguousAddressForms() {
        assertFalse(IpAddressMatcher.matches("localhost", "localhost"));
        assertFalse(IpAddressMatcher.matches("10", "10"));
        assertFalse(IpAddressMatcher.matches("10.0", "10.0"));
        assertFalse(IpAddressMatcher.matches("dead", "dead"));
    }

    @Test
    void validatesIpAddressLiterals() {
        assertTrue(IpAddressMatcher.isIpAddress("10.0.0.1"));
        assertTrue(IpAddressMatcher.isIpAddress("2001:db8::1"));
        assertFalse(IpAddressMatcher.isIpAddress("localhost"));
        assertFalse(IpAddressMatcher.isIpAddress("10.0"));
        assertFalse(IpAddressMatcher.isIpAddress("999.0.0.1"));
    }
}
