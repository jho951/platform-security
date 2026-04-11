package io.github.jho951.platform.security.ip;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import io.github.jho951.platform.security.policy.SecurityBoundary;
import io.github.jho951.platform.security.policy.SecurityBoundaryType;

import java.net.InetAddress;
import java.util.List;
import java.util.Objects;

public final class BoundaryAwareIpPolicy implements SecurityPolicy {
    private final SecurityBoundary boundary;
    private final PlatformSecurityProperties.IpGuardProperties properties;
    private final List<String> allowedCidrs;

    public BoundaryAwareIpPolicy(SecurityBoundary boundary, PlatformSecurityProperties.IpGuardProperties properties, List<String> allowedCidrs) {
        this.boundary = Objects.requireNonNull(boundary, "boundary");
        this.properties = properties == null ? new PlatformSecurityProperties.IpGuardProperties() : properties;
        this.allowedCidrs = allowedCidrs == null ? List.of() : List.copyOf(allowedCidrs);
    }

    @Override
    public String name() {
        return "ip-guard";
    }

    @Override
    public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
        Objects.requireNonNull(request, "request");
        if (!properties.isEnabled() || boundary.type() == SecurityBoundaryType.PUBLIC || allowedCidrs.isEmpty()) return SecurityVerdict.allow(name(), "ip policy disabled");
        for (String cidr : allowedCidrs) {
            if (matches(request.clientIp(), cidr)) {
                return SecurityVerdict.allow(name(), "ip allowed");
            }
        }
        return SecurityVerdict.deny(name(), "ip not allowed: " + request.clientIp());
    }

    private boolean matches(String ip, String cidr) {
        if (ip == null || cidr == null || cidr.isBlank()) return false;
        String trimmed = cidr.trim();
        if (!trimmed.contains("/")) return ip.equals(trimmed);
        String[] parts = trimmed.split("/", 2);
        if (parts.length != 2) return false;
        String base = parts[0].trim();
        int prefixBits;
        try {
            prefixBits = Integer.parseInt(parts[1].trim());
        } catch (NumberFormatException ex) {
            return false;
        }
        try {
            byte[] ipBytes = InetAddress.getByName(ip).getAddress();
            byte[] baseBytes = InetAddress.getByName(base).getAddress();
            if (ipBytes.length != 4 || baseBytes.length != 4 || prefixBits < 0 || prefixBits > 32) return false;
            int fullBytes = prefixBits / 8;
            int remainingBits = prefixBits % 8;
            for (int i = 0; i < fullBytes; i++) {
                if (ipBytes[i] != baseBytes[i]) return false;
            }
            if (remainingBits == 0) return true;
            int mask = 0xFF << (8 - remainingBits);
            return (ipBytes[fullBytes] & mask) == (baseBytes[fullBytes] & mask);
        } catch (Exception ex) {
            return false;
        }
    }
}
