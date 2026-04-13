package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.policy.ClientIpResolver;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;

import java.util.Locale;
import java.util.Map;

public final class DefaultClientIpResolver implements ClientIpResolver {
    private final PlatformSecurityProperties.IpGuardProperties properties;

    public DefaultClientIpResolver(PlatformSecurityProperties.IpGuardProperties properties) {
        this.properties = properties == null ? new PlatformSecurityProperties.IpGuardProperties() : properties;
    }

    @Override
    public String resolve(String remoteAddress, Map<String, String> headers) {
        String fallback = normalize(remoteAddress);
        if (!properties.isTrustProxy()) return fallback;
        if (headers != null) {
            String forwardedFor = header(headers, "X-Forwarded-For");
            if (forwardedFor != null && !forwardedFor.isBlank()) {
                int comma = forwardedFor.indexOf(',');
                return normalize(comma >= 0 ? forwardedFor.substring(0, comma) : forwardedFor);
            }
        }
        return fallback;
    }

    private String header(Map<String, String> headers, String name) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey() != null && entry.getKey().trim().equalsIgnoreCase(name)) return entry.getValue();
        }
        return null;
    }

    private String normalize(String value) {
        if (value == null) return "127.0.0.1";
        String trimmed = value.trim();
        if (trimmed.isEmpty()) return "127.0.0.1";
        return trimmed.toLowerCase(Locale.ROOT).contains("::ffff:")
                ? trimmed.substring(trimmed.lastIndexOf(':') + 1)
                : trimmed;
    }
}
