package io.github.jho951.platform.security.web;

import io.github.jho951.platform.security.policy.ClientIpResolver;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Locale;
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

    private boolean isTrustedProxy(String remoteAddress) {
        if (properties.getTrustedProxyCidrs().isEmpty()) {
            return true;
        }
        for (String cidr : properties.getTrustedProxyCidrs()) {
            if (matchesCidr(remoteAddress, cidr)) {
                return true;
            }
        }
        return false;
    }

    private boolean matchesCidr(String address, String cidr) {
        if (address == null || cidr == null || cidr.isBlank()) {
            return false;
        }
        String normalizedCidr = cidr.trim();
        String network = normalizedCidr;
        int prefixLength;
        int slash = normalizedCidr.indexOf('/');
        if (slash >= 0) {
            network = normalizedCidr.substring(0, slash).trim();
            try {
                prefixLength = Integer.parseInt(normalizedCidr.substring(slash + 1).trim());
            } catch (NumberFormatException exception) {
                return false;
            }
        } else {
            prefixLength = address.contains(":") ? 128 : 32;
        }

        try {
            byte[] addressBytes = InetAddress.getByName(address).getAddress();
            byte[] networkBytes = InetAddress.getByName(normalize(network)).getAddress();
            if (addressBytes.length != networkBytes.length || prefixLength < 0 || prefixLength > addressBytes.length * 8) {
                return false;
            }
            int fullBytes = prefixLength / 8;
            int remainingBits = prefixLength % 8;
            for (int i = 0; i < fullBytes; i++) {
                if (addressBytes[i] != networkBytes[i]) {
                    return false;
                }
            }
            if (remainingBits == 0) {
                return true;
            }
            int mask = 0xFF << (8 - remainingBits);
            return (addressBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
        } catch (UnknownHostException exception) {
            return false;
        }
    }
}
