package io.github.jho951.platform.security.hybrid;

import io.github.jho951.platform.security.api.GatewayUserPrincipal;
import io.github.jho951.platform.security.policy.PlatformSecurityProperties;
import jakarta.servlet.Filter;
import org.springframework.web.server.WebFilter;

import java.util.Map;
import java.util.Optional;

/**
 * gateway header 인증 해석과 filter access를 platform-owned hybrid surface로 묶는다.
 */
public final class HybridHeaderAuthenticationAdapter {
    private final PlatformSecurityProperties.GatewayHeaderProperties properties;
    private final Filter servletFilter;
    private final WebFilter reactiveWebFilter;

    public HybridHeaderAuthenticationAdapter(
            PlatformSecurityProperties.GatewayHeaderProperties properties,
            Filter servletFilter,
            WebFilter reactiveWebFilter
    ) {
        this.properties = properties == null
                ? new PlatformSecurityProperties.GatewayHeaderProperties()
                : properties;
        this.servletFilter = servletFilter;
        this.reactiveWebFilter = reactiveWebFilter;
    }

    public boolean enabled() {
        return properties.isEnabled();
    }

    public Optional<GatewayUserPrincipal> resolve(Map<String, String> headers) {
        if (!enabled()) {
            return Optional.empty();
        }

        String userId = header(headers, properties.getUserIdHeader());
        if (userId == null) {
            return Optional.empty();
        }

        return Optional.of(new GatewayUserPrincipal(
                userId,
                header(headers, properties.getUserStatusHeader())
        ));
    }

    public Optional<Filter> servletFilter() {
        return Optional.ofNullable(servletFilter);
    }

    public Optional<WebFilter> reactiveWebFilter() {
        return Optional.ofNullable(reactiveWebFilter);
    }

    private String header(Map<String, String> headers, String name) {
        if (headers == null || name == null || name.isBlank()) {
            return null;
        }
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey() != null && entry.getKey().trim().equalsIgnoreCase(name)) {
                return trimToNull(entry.getValue());
            }
        }
        return null;
    }

    private static String trimToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }
}
