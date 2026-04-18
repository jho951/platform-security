package io.github.jho951.platform.security.policy;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.Locale;

/**
 * IP exact match와 CIDR match를 제공하는 공통 matcher다.
 */
public final class IpAddressMatcher {
    private IpAddressMatcher() {
    }

    public static boolean matchesAny(String address, Collection<String> rules) {
        if (rules == null || rules.isEmpty()) {
            return false;
        }
        for (String rule : rules) {
            if (matches(address, rule)) {
                return true;
            }
        }
        return false;
    }

    public static boolean matches(String address, String rule) {
        if (address == null || rule == null || rule.isBlank()) {
            return false;
        }
        String normalizedRule = rule.trim();
        int slash = normalizedRule.indexOf('/');
        if (slash >= 0) {
            return matchesCidr(address, normalizedRule, slash);
        }
        return matchesExact(address, normalizedRule);
    }

    public static boolean isIpAddress(String value) {
        try {
            parseIpLiteral(normalize(value));
            return true;
        } catch (UnknownHostException exception) {
            return false;
        }
    }

    public static String normalize(String value) {
        if (value == null) {
            return "";
        }
        String trimmed = value.trim();
        if (trimmed.toLowerCase(Locale.ROOT).contains("::ffff:")) {
            return trimmed.substring(trimmed.lastIndexOf(':') + 1);
        }
        return trimmed;
    }

    private static boolean matchesExact(String address, String expected) {
        String normalizedAddress = normalize(address);
        String normalizedExpected = normalize(expected);
        try {
            byte[] addressBytes = parseIpLiteral(normalizedAddress);
            byte[] expectedBytes = parseIpLiteral(normalizedExpected);
            if (addressBytes.length != expectedBytes.length) {
                return false;
            }
            for (int i = 0; i < addressBytes.length; i++) {
                if (addressBytes[i] != expectedBytes[i]) {
                    return false;
                }
            }
            return true;
        } catch (UnknownHostException exception) {
            return false;
        }
    }

    private static boolean matchesCidr(String address, String cidr, int slash) {
        String network = cidr.substring(0, slash).trim();
        String prefix = cidr.substring(slash + 1).trim();
        if (network.isEmpty() || prefix.isEmpty()) {
            return false;
        }

        int prefixLength;
        try {
            prefixLength = Integer.parseInt(prefix);
        } catch (NumberFormatException exception) {
            return false;
        }

        try {
            byte[] addressBytes = parseIpLiteral(normalize(address));
            byte[] networkBytes = parseIpLiteral(normalize(network));
            int maxPrefixLength = addressBytes.length * 8;
            if (addressBytes.length != networkBytes.length || prefixLength < 0 || prefixLength > maxPrefixLength) {
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

    private static byte[] parseIpLiteral(String value) throws UnknownHostException {
        if (!looksLikeIpLiteral(value)) {
            throw new UnknownHostException(value);
        }
        return InetAddress.getByName(value).getAddress();
    }

    private static boolean looksLikeIpLiteral(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        boolean hasColon = value.indexOf(':') >= 0;
        boolean hasDot = value.indexOf('.') >= 0;
        if (!hasColon && !hasDot) {
            return false;
        }
        if (!hasColon) {
            return looksLikeIpv4Literal(value);
        }
        for (int i = 0; i < value.length(); i++) {
            char current = value.charAt(i);
            boolean allowed = current == '.'
                    || current == ':'
                    || current == '%'
                    || (current >= '0' && current <= '9')
                    || (current >= 'a' && current <= 'f')
                    || (current >= 'A' && current <= 'F');
            if (!allowed) {
                return false;
            }
        }
        return true;
    }

    private static boolean looksLikeIpv4Literal(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) {
                return false;
            }
            int octet = 0;
            for (int i = 0; i < part.length(); i++) {
                char current = part.charAt(i);
                if (current < '0' || current > '9') {
                    return false;
                }
                octet = octet * 10 + current - '0';
            }
            if (octet > 255) {
                return false;
            }
        }
        return true;
    }
}
