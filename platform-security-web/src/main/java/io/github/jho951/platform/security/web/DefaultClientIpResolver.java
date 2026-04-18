package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.policy.ClientIpResolver;
import io.github.jho951.platform.security.policy.IpAddressMatcher;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * remote address와 proxy header를 사용해 client IP를 결정하는 기본 resolver다.
 *
 * <p>{@code trustProxy=true}여도 {@code trustedProxyCidrs}가 설정돼 있으면 신뢰된 proxy에서
 * 들어온 {@code X-Forwarded-For}만 사용한다.</p>
 */
public final class DefaultClientIpResolver implements ClientIpResolver {
    private final PlatformSecurityProperties.IpGuardProperties properties;

    /** @param properties IP guard와 trusted proxy 설정 */
    public DefaultClientIpResolver(PlatformSecurityProperties.IpGuardProperties properties) {
        this.properties = properties == null ? new PlatformSecurityProperties.IpGuardProperties() : properties;
    }

    @Override
    public String resolve(String remoteAddress, Map<String, String> headers) {
        String fallback = normalize(remoteAddress);
        if (!properties.isTrustProxy()) return fallback;
        if (!isTrustedProxy(fallback)) return fallback;
        if (headers != null) {
            String forwardedFor = header(headers, "X-Forwarded-For");
            if (forwardedFor != null && !forwardedFor.isBlank()) {
                return resolveForwardedFor(forwardedFor, fallback);
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
        String normalized = IpAddressMatcher.normalize(value);
        if (normalized.isEmpty()) return "127.0.0.1";
        return normalized;
    }

    private String resolveForwardedFor(String forwardedFor, String fallback) {
        List<String> forwardedIps = forwardedIps(forwardedFor);
        if (forwardedIps.isEmpty()) {
            return fallback;
        }
        for (int i = forwardedIps.size() - 1; i >= 0; i--) {
            String candidate = forwardedIps.get(i);
            if (!isTrustedProxy(candidate)) {
                return candidate;
            }
        }
        return fallback;
    }

    private List<String> forwardedIps(String forwardedFor) {
        String[] parts = forwardedFor.split(",");
        List<String> ips = new ArrayList<>(parts.length);
        for (String part : parts) {
            String normalized = IpAddressMatcher.normalize(part);
            if (!normalized.isEmpty() && IpAddressMatcher.isIpAddress(normalized)) {
                ips.add(normalized);
            }
        }
        return ips;
    }

    private boolean isTrustedProxy(String remoteAddress) {
        if (properties.getTrustedProxyCidrs().isEmpty()) {
            return false;
        }
        return IpAddressMatcher.matchesAny(remoteAddress, properties.getTrustedProxyCidrs());
    }
}
