package io.github.jho951.platform.security.ip;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.stream.Collectors;

final class PlatformIpRuleNormalizer {
    private PlatformIpRuleNormalizer() {
    }

    static String normalizeForEngine(String rules) {
        if (rules == null || rules.isBlank()) {
            return "";
        }
        return Arrays.stream(rules.split("\\R"))
                .map(PlatformIpRuleNormalizer::stripComment)
                .map(String::trim)
                .filter(rule -> !rule.isBlank())
                .map(PlatformIpRuleNormalizer::normalizeRule)
                .collect(Collectors.joining("\n"));
    }

    private static String normalizeRule(String rule) {
        int slash = rule.indexOf('/');
        if (slash <= 0) {
            return rule;
        }

        String address = rule.substring(0, slash).trim();
        String prefix = rule.substring(slash + 1).trim();
        try {
            InetAddress parsed = InetAddress.getByName(address);
            if (!(parsed instanceof Inet4Address)) {
                return rule;
            }
            int prefixBits = Integer.parseInt(prefix);
            if (prefixBits < 0 || prefixBits > 32) {
                return rule;
            }

            long value = ipv4ToLong(parsed.getAddress());
            long mask = prefixBits == 0 ? 0L : 0xFFFFFFFFL << (32 - prefixBits) & 0xFFFFFFFFL;
            long start = value & mask;
            long end = start | (~mask & 0xFFFFFFFFL);
            if (start == end) {
                return longToIpv4(start);
            }
            return longToIpv4(start) + "-" + longToIpv4(end);
        } catch (Exception ignored) {
            return rule;
        }
    }

    private static String stripComment(String rule) {
        int hash = rule.indexOf('#');
        int slashSlash = rule.indexOf("//");
        int cut = -1;
        if (hash >= 0) cut = hash;
        if (slashSlash >= 0) cut = cut < 0 ? slashSlash : Math.min(cut, slashSlash);
        return cut < 0 ? rule : rule.substring(0, cut);
    }

    private static long ipv4ToLong(byte[] bytes) {
        return ((long) bytes[0] & 0xFF) << 24
                | ((long) bytes[1] & 0xFF) << 16
                | ((long) bytes[2] & 0xFF) << 8
                | ((long) bytes[3] & 0xFF);
    }

    private static String longToIpv4(long value) {
        return ((value >>> 24) & 0xFF)
                + "."
                + ((value >>> 16) & 0xFF)
                + "."
                + ((value >>> 8) & 0xFF)
                + "."
                + (value & 0xFF);
    }
}
