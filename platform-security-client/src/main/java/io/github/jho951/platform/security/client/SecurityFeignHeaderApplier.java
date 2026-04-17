package io.github.jho951.platform.security.client;

import java.util.Collection;
import java.util.Map;

/**
 * Feign RequestTemplate 같은 외부 client adapter에서 사용할 수 있는 header applier다.
 */
public final class SecurityFeignHeaderApplier {
    public void apply(Map<String, Collection<String>> headers) {
        if (headers == null) {
            return;
        }
        SecurityOutboundContextHolder.currentHeaders()
                .forEach((name, value) -> headers.put(name, java.util.List.of(value)));
    }
}
