package io.github.jho951.platform.security.policy;

import java.util.Map;

public interface ClientIpResolver {
    String resolve(String remoteAddress, Map<String, String> headers);
}
